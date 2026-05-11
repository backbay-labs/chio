#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use async_trait::async_trait;
use chio_core_types::Keypair;
use chio_federation::{
    PheromoneDepositGossip, PheromoneGossipBatch, PHEROMONE_GOSSIP_BATCH_SCHEMA,
    PHEROMONE_GOSSIP_SCHEMA,
};
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, sign_deposit, PheromoneDepositBody,
    Severity, PHEROMONE_DEPOSIT_SCHEMA,
};
use chio_pheromone_relay::{
    sign_relay_http_request, CatchupRequest, CatchupResponse, PeerDirectory, PeerDirectoryDocument,
    PeerDirectoryEntry, PheromoneRelayClient, PheromoneRelayConfig, PheromoneRelayError,
    PheromoneRelayService, RelayBatchReceiver, RelayHttpSigningInput, RelayHttpVerificationContext,
    RelayLadderRef, RelayNonceRecorder, RelayNonceSet, RelayRole, SqlitePheromoneRelayStore,
    PHEROMONE_BATCH_RELAY_PATH, PHEROMONE_CATCHUP_RELAY_PATH, PHEROMONE_CATCHUP_REQUEST_SCHEMA,
    PHEROMONE_PEER_DIRECTORY_SCHEMA,
};
use chio_pheromone_runtime::{
    PheromoneFrameReport, PheromoneReceiveReport, PHEROMONE_RECEIVE_REPORT_SCHEMA,
};
use serde_json::json;

const NOW: u64 = 1_766_000_000_500;

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn sample_batch() -> PheromoneGossipBatch {
    let passport_key = key(31);
    let public_key = passport_key.public_key();
    let deposit = sign_deposit(
        PheromoneDepositBody {
            schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
            kernel_id: "did:chio:llamaworks".to_string(),
            agent_passport_key_hash: agent_passport_key_hash(&public_key),
            agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public_key),
            subject_class: "support.prompt_injection".to_string(),
            subject_class_namespace: "dev.chio.support".to_string(),
            indicator: json!({"digest": "a".repeat(64)}),
            severity: Severity::High,
            confidence: 0.8,
            timestamp_unix_ms: NOW,
            decay_half_life_secs: 3_600.0,
            evaporation_floor: Some(0.01),
            nonce: "nonce-live-relay-001".to_string(),
            treaty_scope: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            cost_commitment: None,
            workflow_context: None,
        },
        &passport_key,
    )
    .unwrap();
    PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
        frames: vec![PheromoneDepositGossip {
            schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
            deposit,
            origin_kernel_id: "did:chio:llamaworks".to_string(),
            gossiping_peer_kernel_id: "did:chio:llamaworks".to_string(),
            treaty_id: "treaty:buyer-llamaworks:support-ops".to_string(),
            ts_unix_ms: NOW,
            transit_chain: None,
        }],
        flushed_at_unix_ms: NOW,
    }
}

fn directory(sender: &Keypair, endpoint: String) -> PeerDirectoryDocument {
    PeerDirectoryDocument {
        schema: PHEROMONE_PEER_DIRECTORY_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        peers: vec![PeerDirectoryEntry {
            kernel_id: "did:chio:llamaworks".to_string(),
            public_key: sender.public_key(),
            endpoint,
            treaty_subscriptions: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            relay_role: RelayRole::Origin,
            allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
            accepted_ladder_refs: vec![RelayLadderRef {
                ladder_manifest_id: "ladder:llamaworks:support:v1".to_string(),
                ladder_manifest_sha256: "a".repeat(64),
                expires_at_unix_ms: NOW + 60_000,
            }],
            max_batch_frames: 8,
            max_catchup_frames: 16,
            max_catchup_bytes: 64_000,
        }],
    }
}

fn client_directory(recipient: &Keypair, endpoint: String) -> PeerDirectoryDocument {
    PeerDirectoryDocument {
        schema: PHEROMONE_PEER_DIRECTORY_SCHEMA.to_string(),
        local_kernel_id: "did:chio:llamaworks".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        peers: vec![PeerDirectoryEntry {
            kernel_id: "did:chio:buyer-kernel".to_string(),
            public_key: recipient.public_key(),
            endpoint,
            treaty_subscriptions: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            relay_role: RelayRole::Receiver,
            allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
            accepted_ladder_refs: vec![RelayLadderRef {
                ladder_manifest_id: "ladder:buyer:support:v1".to_string(),
                ladder_manifest_sha256: "b".repeat(64),
                expires_at_unix_ms: NOW + 60_000,
            }],
            max_batch_frames: 8,
            max_catchup_frames: 16,
            max_catchup_bytes: 64_000,
        }],
    }
}

#[test]
fn peer_directory_rejects_duplicate_peer_ids() {
    let sender = key(1);
    let mut document = directory(&sender, "http://127.0.0.1:18080".to_string());
    document.peers.push(document.peers[0].clone());

    let err = PeerDirectory::from_document(document, NOW).unwrap_err();

    assert_eq!(err.code(), "duplicate_peer");
}

#[test]
fn signed_relay_request_verifies_payload_hash_sender_and_replay_nonce() {
    let sender = key(1);
    let document = directory(&sender, "http://127.0.0.1:18080".to_string());
    let directory = PeerDirectory::from_document(document, NOW).unwrap();
    let batch = sample_batch();
    let request = sign_relay_http_request(RelayHttpSigningInput {
        sender_kernel_id: "did:chio:llamaworks",
        recipient_kernel_id: "did:chio:buyer-kernel",
        method: "POST",
        path: PHEROMONE_BATCH_RELAY_PATH,
        nonce: "relay-nonce-001",
        sent_at_unix_ms: NOW,
        payload: &batch,
        keypair: &sender,
    })
    .unwrap();
    let context = RelayHttpVerificationContext {
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        method: "POST".to_string(),
        path: PHEROMONE_BATCH_RELAY_PATH.to_string(),
        now_unix_ms: NOW,
        freshness_window_ms: 60_000,
    };
    let nonces = RelayNonceSet::default();

    let verified: PheromoneGossipBatch = request
        .verify_payload(&directory, &context, &nonces)
        .unwrap();
    assert_eq!(verified, batch);

    let replay = request
        .verify_payload::<PheromoneGossipBatch>(&directory, &context, &nonces)
        .unwrap_err();
    assert_eq!(replay.code(), "relay_nonce_replay");

    let mut tampered = request.clone();
    tampered.payload["treaty_id"] = json!("treaty:attacker");
    let mismatch = tampered
        .verify_payload::<PheromoneGossipBatch>(&directory, &context, &RelayNonceSet::default())
        .unwrap_err();
    assert_eq!(mismatch.code(), "body_hash_mismatch");
}

#[test]
fn relay_store_leases_due_batches_and_records_idempotent_inbox() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRelayStore::open(temp.path().join("relay.sqlite3")).unwrap();
    let batch = sample_batch();
    let outbox_id = store
        .enqueue_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &batch.treaty_id,
            &batch,
            NOW,
        )
        .unwrap();

    let (catchup_frames, next_cursor) = store
        .catchup_batches("did:chio:buyer-kernel", &batch.treaty_id, "0", 4, 256_000)
        .unwrap();
    assert_eq!(catchup_frames, vec![batch.clone()]);
    assert_ne!(next_cursor, "0");
    assert_eq!(
        store
            .catchup_batches(
                "did:chio:buyer-kernel",
                &batch.treaty_id,
                &next_cursor,
                4,
                256_000
            )
            .unwrap()
            .0,
        Vec::<PheromoneGossipBatch>::new()
    );
    assert_eq!(
        store
            .catchup_batches("did:chio:buyer-kernel", &batch.treaty_id, "0", 0, 256_000)
            .unwrap_err()
            .code(),
        "catchup_denied"
    );

    let first_due = store.lease_due_batches(NOW, 4).unwrap();
    assert_eq!(first_due.len(), 1);
    assert_eq!(first_due[0].outbox_id, outbox_id);
    assert!(store.lease_due_batches(NOW, 4).unwrap().is_empty());

    store
        .mark_retry(&outbox_id, "transport_error", NOW + 5_000)
        .unwrap();
    assert!(store.lease_due_batches(NOW + 4_999, 4).unwrap().is_empty());
    assert_eq!(store.lease_due_batches(NOW + 5_000, 4).unwrap().len(), 1);

    store
        .record_relay_nonce("did:chio:llamaworks", "relay-nonce-001", NOW + 60_000)
        .unwrap();
    let replay = store
        .record_relay_nonce("did:chio:llamaworks", "relay-nonce-001", NOW + 120_000)
        .unwrap_err();
    assert_eq!(replay.code(), "relay_nonce_replay");

    let report = accepted_report();
    assert!(
        store
            .record_inbox("did:chio:llamaworks", "relay-nonce-001", &batch, &report)
            .unwrap()
            .inserted
    );
    assert!(
        !store
            .record_inbox("did:chio:llamaworks", "relay-nonce-001", &batch, &report)
            .unwrap()
            .inserted
    );
}

#[tokio::test]
async fn loopback_http_delivery_posts_signed_batch_to_receiver() {
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
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
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

#[derive(Debug)]
struct AcceptingReceiver;

#[async_trait]
impl RelayBatchReceiver for AcceptingReceiver {
    async fn receive_batch(
        &self,
        batch: PheromoneGossipBatch,
        authenticated_sender_kernel_id: String,
        received_at_unix_ms: u64,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
        assert_eq!(authenticated_sender_kernel_id, "did:chio:llamaworks");
        Ok(PheromoneReceiveReport {
            schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
            accepted: true,
            batch_sha256: chio_core_types::crypto::sha256_hex(
                &chio_core_types::canonical::canonical_json_bytes(&batch).unwrap(),
            ),
            recipient_kernel_id: batch.recipient_kernel_id,
            authenticated_sender_kernel_id,
            received_at_unix_ms,
            frames: vec![PheromoneFrameReport {
                frame_index: 0,
                accepted: true,
                code: "accepted".to_string(),
                detail: "accepted".to_string(),
                deposit_nonce: Some("nonce-live-relay-001".to_string()),
            }],
        })
    }
}

fn accepted_report() -> PheromoneReceiveReport {
    PheromoneReceiveReport {
        schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
        accepted: true,
        batch_sha256: "b".repeat(64),
        recipient_kernel_id: "did:chio:buyer-kernel".to_string(),
        authenticated_sender_kernel_id: "did:chio:llamaworks".to_string(),
        received_at_unix_ms: NOW,
        frames: vec![PheromoneFrameReport {
            frame_index: 0,
            accepted: true,
            code: "accepted".to_string(),
            detail: "accepted".to_string(),
            deposit_nonce: Some("nonce-live-relay-001".to_string()),
        }],
    }
}
