use super::common::{
    alert_profile, client_directory, degraded_observability_report, deliver_due_batches, directory,
    generate_relay_trend_report, key, relay_alert_routing_profile_from_json, sample_batch,
    sign_relay_http_request, AcceptingReceiver, Arc, CatchupRequest, CatchupResponse,
    PeerDirectory, PheromoneRelayClient, PheromoneRelayConfig, PheromoneRelayService,
    PheromoneTransitChain, PheromoneTransitHop, RelayEventReport, RelayHttpSigningInput,
    RelayProfile, RelayRole, RelayTrendInput, SqlitePheromoneRelayStore, NOW,
    PHEROMONE_BATCH_RELAY_PATH, PHEROMONE_CATCHUP_RELAY_PATH, PHEROMONE_CATCHUP_REQUEST_SCHEMA,
    PHEROMONE_RELAY_OBSERVABILITY_PATH, PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
};

#[test]
fn relay_trend_report_aggregates_bounded_codes() {
    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let report = generate_relay_trend_report(RelayTrendInput {
        local_kernel_id: "did:chio:buyer-kernel",
        observability_reports: &[degraded_observability_report()],
        event_reports: &[RelayEventReport {
            schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
            accepted: false,
            code: "endpoint_denied".to_string(),
            detail: "endpoint rejected".to_string(),
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            generated_at_unix_ms: NOW + 1_000,
            event_kind: "request_rejected".to_string(),
            stable_failure_code: Some("endpoint_denied".to_string()),
        }],
        routing_profile: &profile,
        since_unix_ms: NOW - 60_000,
        until_unix_ms: NOW + 60_000,
    })
    .unwrap();

    assert_eq!(report.schema, PHEROMONE_RELAY_TREND_REPORT_SCHEMA);
    assert!(report.accepted);
    assert_eq!(report.source_report_count, 1);
    assert_eq!(report.event_report_count, 1);
    assert!(report
        .points
        .iter()
        .any(|point| point.code == "dead_letters_present" && point.count == 1));
    assert!(report
        .points
        .iter()
        .all(|point| !point.code.contains("did:chio") && !point.code.contains("treaty:")));
}

#[tokio::test]
async fn relay_observability_endpoint_requires_operator_token_when_configured() {
    let sender = key(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let directory =
        PeerDirectory::from_document(directory(&sender, format!("http://{address}")), NOW).unwrap();
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: Some("operator-secret".to_string()),
            report_dir: None,
        },
        directory,
        Arc::new(AcceptingReceiver),
        Arc::clone(&store),
    );
    let server = tokio::spawn(service.serve(listener));
    let client = reqwest::Client::new();

    let denied = client
        .get(format!(
            "http://{address}{PHEROMONE_RELAY_OBSERVABILITY_PATH}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);

    let accepted = client
        .get(format!(
            "http://{address}{PHEROMONE_RELAY_OBSERVABILITY_PATH}"
        ))
        .bearer_auth("operator-secret")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(
        accepted["schema"].as_str(),
        Some(PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA)
    );
    assert_eq!(
        accepted["directory"]["profile"].as_str(),
        Some("production")
    );
    server.abort();
}

#[tokio::test]
async fn relay_rejects_authenticated_batch_above_peer_frame_limit() {
    let sender = key(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let receiver_directory =
        PeerDirectory::from_document(directory(&sender, format!("http://{address}")), NOW).unwrap();
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: None,
        },
        receiver_directory,
        Arc::new(AcceptingReceiver),
        Arc::clone(&store),
    );
    let server = tokio::spawn(service.serve(listener));

    let mut batch = sample_batch();
    let frame = batch.frames[0].clone();
    batch.frames = vec![frame; 9];
    let request = sign_relay_http_request(RelayHttpSigningInput {
        sender_kernel_id: "did:chio:llamaworks",
        recipient_kernel_id: "did:chio:buyer-kernel",
        method: "POST",
        path: PHEROMONE_BATCH_RELAY_PATH,
        nonce: "relay-nonce-over-peer-limit",
        sent_at_unix_ms: NOW,
        payload: &batch,
        keypair: &sender,
    })
    .unwrap();
    let response = reqwest::Client::new()
        .post(format!("http://{address}{PHEROMONE_BATCH_RELAY_PATH}"))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let report = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(report["code"].as_str(), Some("relay_profile_denied"));
    assert!(report["detail"]
        .as_str()
        .unwrap()
        .contains("submitted 9 batch frames"));
    server.abort();
}

#[tokio::test]
async fn relay_rejects_authenticated_batch_for_unsubscribed_treaty() {
    let sender = key(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let receiver_directory =
        PeerDirectory::from_document(directory(&sender, format!("http://{address}")), NOW).unwrap();
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: None,
        },
        receiver_directory,
        Arc::new(AcceptingReceiver),
        Arc::clone(&store),
    );
    let server = tokio::spawn(service.serve(listener));

    let mut batch = sample_batch();
    batch.treaty_id = "treaty:buyer-llamaworks:unauthorized".to_string();
    for frame in &mut batch.frames {
        frame.treaty_id = batch.treaty_id.clone();
    }
    let request = sign_relay_http_request(RelayHttpSigningInput {
        sender_kernel_id: "did:chio:llamaworks",
        recipient_kernel_id: "did:chio:buyer-kernel",
        method: "POST",
        path: PHEROMONE_BATCH_RELAY_PATH,
        nonce: "relay-nonce-unsubscribed-treaty",
        sent_at_unix_ms: NOW,
        payload: &batch,
        keypair: &sender,
    })
    .unwrap();
    let response = reqwest::Client::new()
        .post(format!("http://{address}{PHEROMONE_BATCH_RELAY_PATH}"))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let report = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(report["code"].as_str(), Some("relay_profile_denied"));
    assert!(report["detail"]
        .as_str()
        .unwrap()
        .contains("is not subscribed to treaty"));
    server.abort();
}

#[tokio::test]
async fn relay_rejects_authenticated_batch_from_non_origin_peer_role() {
    let sender = key(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut document = directory(&sender, format!("http://{address}"));
    document.peers[0].relay_role = RelayRole::Receiver;
    let receiver_directory = PeerDirectory::from_document(document, NOW).unwrap();
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: None,
        },
        receiver_directory,
        Arc::new(AcceptingReceiver),
        Arc::clone(&store),
    );
    let server = tokio::spawn(service.serve(listener));

    let batch = sample_batch();
    let request = sign_relay_http_request(RelayHttpSigningInput {
        sender_kernel_id: "did:chio:llamaworks",
        recipient_kernel_id: "did:chio:buyer-kernel",
        method: "POST",
        path: PHEROMONE_BATCH_RELAY_PATH,
        nonce: "relay-nonce-wrong-role",
        sent_at_unix_ms: NOW,
        payload: &batch,
        keypair: &sender,
    })
    .unwrap();
    let response = reqwest::Client::new()
        .post(format!("http://{address}{PHEROMONE_BATCH_RELAY_PATH}"))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let report = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(report["code"].as_str(), Some("relay_profile_denied"));
    assert!(report["detail"]
        .as_str()
        .unwrap()
        .contains("not authorized to submit inbound batches"));
    server.abort();
}

#[tokio::test]
async fn relay_rejects_authenticated_batch_with_unpinned_transit_ladder() {
    let sender = key(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let receiver_directory =
        PeerDirectory::from_document(directory(&sender, format!("http://{address}")), NOW).unwrap();
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: None,
        },
        receiver_directory,
        Arc::new(AcceptingReceiver),
        Arc::clone(&store),
    );
    let server = tokio::spawn(service.serve(listener));

    let mut batch = sample_batch();
    batch.frames[0].transit_chain = Some(PheromoneTransitChain {
        hops: vec![PheromoneTransitHop {
            from_kernel_id: "did:chio:llamaworks".to_string(),
            to_kernel_id: "did:chio:buyer-kernel".to_string(),
            treaty_id: batch.treaty_id.clone(),
            ladder_manifest_id: "ladder:llamaworks:untrusted:v1".to_string(),
            ladder_manifest_sha256: "f".repeat(64),
            ladder_manifest_expires_at_unix_ms: NOW + 60_000,
            ladder_intersection_id: "intersection:buyer:llamaworks".to_string(),
            action_class_id: "whisker.pheromone_deposit".to_string(),
            emitted_at_unix_ms: NOW,
        }],
    });
    let request = sign_relay_http_request(RelayHttpSigningInput {
        sender_kernel_id: "did:chio:llamaworks",
        recipient_kernel_id: "did:chio:buyer-kernel",
        method: "POST",
        path: PHEROMONE_BATCH_RELAY_PATH,
        nonce: "relay-nonce-unpinned-ladder",
        sent_at_unix_ms: NOW,
        payload: &batch,
        keypair: &sender,
    })
    .unwrap();
    let response = reqwest::Client::new()
        .post(format!("http://{address}{PHEROMONE_BATCH_RELAY_PATH}"))
        .json(&request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let report = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(report["code"].as_str(), Some("relay_profile_denied"));
    assert!(report["detail"]
        .as_str()
        .unwrap()
        .contains("transit ladder"));
    server.abort();
}

#[tokio::test]
async fn loopback_http_delivery_posts_signed_batch_to_receiver() {
    let sender = key(1);
    let recipient = key(2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut receiver_directory_document = directory(&sender, format!("http://{address}"));
    receiver_directory_document.peers[0].relay_role = RelayRole::Hub;
    let receiver_directory =
        PeerDirectory::from_document(receiver_directory_document, NOW).unwrap();
    let sender_directory = PeerDirectory::from_document(
        client_directory(&recipient, format!("http://{address}")),
        NOW,
    )
    .unwrap();
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let mut catchup_batch = sample_batch();
    catchup_batch.recipient_kernel_id = "did:chio:llamaworks".to_string();
    store
        .enqueue_batch(
            "did:chio:buyer-kernel",
            "did:chio:llamaworks",
            &catchup_batch.treaty_id,
            &catchup_batch,
            NOW,
        )
        .unwrap();
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::LocalDev,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: None,
        },
        receiver_directory,
        Arc::new(AcceptingReceiver),
        Arc::clone(&store),
    );
    let server = tokio::spawn(service.serve(listener));

    let client = PheromoneRelayClient::new(sender_directory, sender.clone(), NOW, 60_000).unwrap();
    let report = client
        .post_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &sample_batch(),
            "relay-nonce-loopback",
        )
        .await
        .unwrap();

    assert!(report.accepted);
    let catchup = CatchupRequest {
        schema: PHEROMONE_CATCHUP_REQUEST_SCHEMA.to_string(),
        requester_kernel_id: "did:chio:llamaworks".to_string(),
        responder_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        after_cursor: "0".to_string(),
        limit: 4,
    };
    let signed_catchup = sign_relay_http_request(RelayHttpSigningInput {
        sender_kernel_id: "did:chio:llamaworks",
        recipient_kernel_id: "did:chio:buyer-kernel",
        method: "POST",
        path: PHEROMONE_CATCHUP_RELAY_PATH,
        nonce: "relay-nonce-catchup",
        sent_at_unix_ms: NOW,
        payload: &catchup,
        keypair: &sender,
    })
    .unwrap();
    let catchup_response: CatchupResponse = reqwest::Client::new()
        .post(format!("http://{address}{PHEROMONE_CATCHUP_RELAY_PATH}"))
        .json(&signed_catchup)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(catchup_response.accepted);
    assert_eq!(catchup_response.frames, vec![catchup_batch]);
    server.abort();
}

#[tokio::test]
async fn relay_catchup_rejects_origin_only_peer_role() {
    let sender = key(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let receiver_directory =
        PeerDirectory::from_document(directory(&sender, format!("http://{address}")), NOW).unwrap();
    let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: None,
        },
        receiver_directory,
        Arc::new(AcceptingReceiver),
        Arc::clone(&store),
    );
    let server = tokio::spawn(service.serve(listener));

    let catchup = CatchupRequest {
        schema: PHEROMONE_CATCHUP_REQUEST_SCHEMA.to_string(),
        requester_kernel_id: "did:chio:llamaworks".to_string(),
        responder_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        after_cursor: "0".to_string(),
        limit: 4,
    };
    let signed_catchup = sign_relay_http_request(RelayHttpSigningInput {
        sender_kernel_id: "did:chio:llamaworks",
        recipient_kernel_id: "did:chio:buyer-kernel",
        method: "POST",
        path: PHEROMONE_CATCHUP_RELAY_PATH,
        nonce: "relay-nonce-catchup-origin-only",
        sent_at_unix_ms: NOW,
        payload: &catchup,
        keypair: &sender,
    })
    .unwrap();
    let response = reqwest::Client::new()
        .post(format!("http://{address}{PHEROMONE_CATCHUP_RELAY_PATH}"))
        .json(&signed_catchup)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let report = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(report["code"].as_str(), Some("catchup_denied"));
    assert!(report["detail"]
        .as_str()
        .unwrap()
        .contains("not authorized for catch-up"));
    server.abort();
}

#[tokio::test]
async fn relay_tick_delivers_leased_batches_with_real_request_signature() {
    let sender = key(1);
    let recipient = key(2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let receiver_directory =
        PeerDirectory::from_document(directory(&sender, format!("http://{address}")), NOW).unwrap();
    let sender_directory = PeerDirectory::from_document(
        client_directory(&recipient, format!("http://{address}")),
        NOW,
    )
    .unwrap();
    let receiver_store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: "did:chio:buyer-kernel".to_string(),
            profile: RelayProfile::LocalDev,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: None,
        },
        receiver_directory,
        Arc::new(AcceptingReceiver),
        receiver_store,
    );
    let server = tokio::spawn(service.serve(listener));
    let outbox_store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let batch = sample_batch();
    outbox_store
        .enqueue_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &batch.treaty_id,
            &batch,
            NOW,
        )
        .unwrap();

    let report = deliver_due_batches(
        &outbox_store,
        sender_directory,
        sender,
        "did:chio:llamaworks",
        NOW,
        4,
    )
    .await
    .unwrap();

    assert!(report.accepted);
    assert_eq!(report.delivered, 1);
    assert_eq!(report.retried, 0);
    assert_eq!(report.dead_lettered, 0);
    assert!(report.failures.is_empty());
    assert!(outbox_store
        .lease_due_batches(NOW + 60_000, 4)
        .unwrap()
        .is_empty());
    server.abort();
}

#[tokio::test]
async fn relay_tick_rechecks_recipient_scope_before_delivery() {
    let sender = key(1);
    let recipient = key(2);
    let mut sender_directory_document =
        client_directory(&recipient, "http://127.0.0.1:9".to_string());
    sender_directory_document.peers[0]
        .treaty_subscriptions
        .clear();
    let sender_directory = PeerDirectory::from_document(sender_directory_document, NOW).unwrap();
    let outbox_store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let batch = sample_batch();
    outbox_store
        .enqueue_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &batch.treaty_id,
            &batch,
            NOW,
        )
        .unwrap();

    let report = deliver_due_batches(
        &outbox_store,
        sender_directory,
        sender,
        "did:chio:llamaworks",
        NOW,
        4,
    )
    .await
    .unwrap();

    assert!(!report.accepted);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.retried, 1);
    assert!(report
        .failures
        .iter()
        .any(|failure| failure.contains("relay_profile_denied")));
}

#[tokio::test]
async fn relay_tick_rejects_recipient_without_receiver_role_before_delivery() {
    let sender = key(1);
    let recipient = key(2);
    let mut sender_directory_document =
        client_directory(&recipient, "http://127.0.0.1:9".to_string());
    sender_directory_document.peers[0].relay_role = RelayRole::Origin;
    let sender_directory = PeerDirectory::from_document(sender_directory_document, NOW).unwrap();
    let outbox_store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let batch = sample_batch();
    outbox_store
        .enqueue_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &batch.treaty_id,
            &batch,
            NOW,
        )
        .unwrap();

    let report = deliver_due_batches(
        &outbox_store,
        sender_directory,
        sender,
        "did:chio:llamaworks",
        NOW,
        4,
    )
    .await
    .unwrap();

    assert!(!report.accepted);
    assert_eq!(report.delivered, 0);
    assert_eq!(report.retried, 1);
    assert!(report
        .failures
        .iter()
        .any(|failure| failure.contains("relay_profile_denied")));
}
