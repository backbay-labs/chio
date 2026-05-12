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
    deliver_due_batches, evaluate_relay_alert_handoff, evaluate_relay_alerts,
    generate_relay_trend_report, promote_peer_directory_candidate,
    relay_alert_handoff_profile_from_json, relay_alert_routing_profile_from_json,
    relay_alert_suppression_state_from_json, sign_peer_directory_bundle, sign_relay_http_request,
    CatchupRequest, CatchupResponse, PeerDirectory, PeerDirectoryBundleSigningInput,
    PeerDirectoryBundleTrust, PeerDirectoryDocument, PeerDirectoryEntry,
    PeerDirectoryStateDocument, PheromoneRelayClient, PheromoneRelayConfig, PheromoneRelayError,
    PheromoneRelayService, RelayAlertEvaluationInput, RelayAlertHandoffEscalation,
    RelayAlertHandoffInput, RelayAlertHandoffProfileDocument, RelayAlertHandoffReceiver,
    RelayAlertHandoffSinkKind, RelayAlertRoute, RelayAlertRouteKind,
    RelayAlertRoutingProfileDocument, RelayAlertRule, RelayAlertSeverity,
    RelayAlertSuppressionEntry, RelayAlertSuppressionStateDocument, RelayBatchReceiver,
    RelayEventReport, RelayHttpSigningInput, RelayHttpVerificationContext, RelayLadderRef,
    RelayMetricsFormat, RelayNonceRecorder, RelayNonceSet, RelayObservabilityInput,
    RelayObservabilityReport, RelayProfile, RelayProfileLimits, RelayRole, RelayTrendInput,
    SqlitePheromoneRelayStore, TrustedPeerDirectoryIssuer, PHEROMONE_BATCH_RELAY_PATH,
    PHEROMONE_CATCHUP_RELAY_PATH, PHEROMONE_CATCHUP_REQUEST_SCHEMA,
    PHEROMONE_PEER_DIRECTORY_SCHEMA, PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA, PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA,
    PHEROMONE_RELAY_OBSERVABILITY_PATH, PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA, PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
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
fn signed_peer_directory_bundle_verifies_trust_and_rejects_rollback() {
    let issuer = key(9);
    let sender = key(1);
    let document = directory(&sender, "https://relay.example.test".to_string());
    let bundle = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 3,
        previous_version_sha256: Some("c".repeat(64)),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &document,
        keypair: &issuer,
    })
    .unwrap();
    let trust = PeerDirectoryBundleTrust {
        issuers: vec![TrustedPeerDirectoryIssuer {
            issuer: "did:chio:relay-ops".to_string(),
            key_id: "relay-ops-2026".to_string(),
            public_key: issuer.public_key(),
        }],
        min_version: 3,
        now_unix_ms: NOW,
        profile: RelayProfile::Production,
        limits: RelayProfileLimits::production_defaults(),
    };

    let verified = bundle.verify(&trust).unwrap();

    assert_eq!(verified.local_kernel_id(), "did:chio:buyer-kernel");
    assert_eq!(verified.version(), Some(3));

    let mut rollback_trust = trust.clone();
    rollback_trust.min_version = 4;
    let rollback = bundle.verify(&rollback_trust).unwrap_err();
    assert_eq!(rollback.code(), "peer_directory_rollback");

    let mut unknown_issuer = trust;
    unknown_issuer.issuers.clear();
    let unknown = bundle.verify(&unknown_issuer).unwrap_err();
    assert_eq!(unknown.code(), "unknown_peer_directory_issuer");
}

#[test]
fn peer_directory_state_promotes_only_continuous_candidates() {
    let issuer = key(9);
    let sender = key(1);
    let first = directory(&sender, "https://relay-v1.example.test".to_string());
    let first_bundle = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 1,
        previous_version_sha256: None,
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &first,
        keypair: &issuer,
    })
    .unwrap();
    let mut state = PeerDirectoryStateDocument::new("did:chio:buyer-kernel", NOW);
    let trust = PeerDirectoryBundleTrust {
        issuers: vec![TrustedPeerDirectoryIssuer {
            issuer: "did:chio:relay-ops".to_string(),
            key_id: "relay-ops-2026".to_string(),
            public_key: issuer.public_key(),
        }],
        min_version: 1,
        now_unix_ms: NOW,
        profile: RelayProfile::Production,
        limits: RelayProfileLimits::production_defaults(),
    };

    let first_report =
        promote_peer_directory_candidate(&mut state, first_bundle, &trust, NOW).unwrap();
    assert!(first_report.accepted);
    assert_eq!(state.active.as_ref().unwrap().version, 1);
    let active = state.active_directory(&trust).unwrap();
    let active_hash = state.active.as_ref().unwrap().bundle_sha256.clone();
    assert_eq!(active.version(), Some(1));

    let mut second = first.clone();
    second.peers[0].endpoint = "https://relay-v2.example.test".to_string();
    let broken_candidate = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 2,
        previous_version_sha256: Some("f".repeat(64)),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &second,
        keypair: &issuer,
    })
    .unwrap();

    let broken =
        promote_peer_directory_candidate(&mut state, broken_candidate, &trust, NOW).unwrap_err();
    assert_eq!(broken.code(), "peer_directory_rollback");
    assert_eq!(state.active.as_ref().unwrap().version, 1);
    assert!(!state.rejected.is_empty());

    let continuous = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 2,
        previous_version_sha256: Some(active_hash),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &second,
        keypair: &issuer,
    })
    .unwrap();
    let second_report =
        promote_peer_directory_candidate(&mut state, continuous, &trust, NOW).unwrap();
    assert!(second_report.accepted);
    assert_eq!(state.active.as_ref().unwrap().version, 2);
}

#[test]
fn peer_directory_state_quarantines_removed_peers() {
    let issuer = key(9);
    let sender = key(1);
    let mut first = directory(&sender, "https://relay-v1.example.test".to_string());
    first.peers.push(PeerDirectoryEntry {
        kernel_id: "did:chio:removed-peer".to_string(),
        public_key: key(44).public_key(),
        endpoint: "https://removed.example.test".to_string(),
        treaty_subscriptions: vec!["treaty:buyer-removed:support-ops".to_string()],
        relay_role: RelayRole::Origin,
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        accepted_ladder_refs: first.peers[0].accepted_ladder_refs.clone(),
        max_batch_frames: 8,
        max_catchup_frames: 16,
        max_catchup_bytes: 64_000,
    });
    let first_bundle = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 1,
        previous_version_sha256: None,
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &first,
        keypair: &issuer,
    })
    .unwrap();
    let trust = PeerDirectoryBundleTrust {
        issuers: vec![TrustedPeerDirectoryIssuer {
            issuer: "did:chio:relay-ops".to_string(),
            key_id: "relay-ops-2026".to_string(),
            public_key: issuer.public_key(),
        }],
        min_version: 1,
        now_unix_ms: NOW,
        profile: RelayProfile::Production,
        limits: RelayProfileLimits::production_defaults(),
    };
    let mut state = PeerDirectoryStateDocument::new("did:chio:buyer-kernel", NOW);
    promote_peer_directory_candidate(&mut state, first_bundle, &trust, NOW).unwrap();
    let active_hash = state.active.as_ref().unwrap().bundle_sha256.clone();

    let mut second = first.clone();
    second
        .peers
        .retain(|peer| peer.kernel_id != "did:chio:removed-peer");
    let second_bundle = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 2,
        previous_version_sha256: Some(active_hash),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &second,
        keypair: &issuer,
    })
    .unwrap();

    let report = promote_peer_directory_candidate(&mut state, second_bundle, &trust, NOW).unwrap();
    assert_eq!(report.removed_peer_ids, vec!["did:chio:removed-peer"]);
    let active = state.active_directory(&trust).unwrap();
    let removed = active.peer("did:chio:removed-peer").unwrap_err();
    assert_eq!(removed.code(), "peer_removed");

    let second_active_hash = state.active.as_ref().unwrap().bundle_sha256.clone();
    let mut third = second.clone();
    third.peers[0].endpoint = "https://relay-v3.example.test".to_string();
    let third_bundle = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 3,
        previous_version_sha256: Some(second_active_hash),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &third,
        keypair: &issuer,
    })
    .unwrap();

    let third_report =
        promote_peer_directory_candidate(&mut state, third_bundle, &trust, NOW).unwrap();
    assert_eq!(third_report.removed_peer_ids, vec!["did:chio:removed-peer"]);
    let active = state.active_directory(&trust).unwrap();
    let removed = active.peer("did:chio:removed-peer").unwrap_err();
    assert_eq!(removed.code(), "peer_removed");

    let third_active_hash = state.active.as_ref().unwrap().bundle_sha256.clone();
    let mut fourth = third;
    fourth.peers.push(first.peers[1].clone());
    let fourth_bundle = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 4,
        previous_version_sha256: Some(third_active_hash),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &fourth,
        keypair: &issuer,
    })
    .unwrap();

    let fourth_report =
        promote_peer_directory_candidate(&mut state, fourth_bundle, &trust, NOW).unwrap();
    assert!(fourth_report.removed_peer_ids.is_empty());
    let active = state.active_directory(&trust).unwrap();
    assert_eq!(
        active.peer("did:chio:removed-peer").unwrap().kernel_id,
        "did:chio:removed-peer"
    );
}

#[test]
fn relay_profiles_reject_unsafe_production_endpoints() {
    let sender = key(1);
    let loopback = directory(&sender, "http://127.0.0.1:18080".to_string());
    let limits = RelayProfileLimits::production_defaults();

    PeerDirectory::from_document_with_profile(
        loopback.clone(),
        NOW,
        RelayProfile::LocalDev,
        &limits,
    )
    .unwrap();

    let denied =
        PeerDirectory::from_document_with_profile(loopback, NOW, RelayProfile::Production, &limits)
            .unwrap_err();
    assert_eq!(denied.code(), "endpoint_denied");

    let mut excessive = directory(&sender, "https://relay.example.test".to_string());
    excessive.peers[0].max_catchup_bytes = limits.max_catchup_bytes + 1;
    let over_limit = PeerDirectory::from_document_with_profile(
        excessive,
        NOW,
        RelayProfile::Production,
        &limits,
    )
    .unwrap_err();
    assert_eq!(over_limit.code(), "relay_profile_denied");
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

#[test]
fn relay_observability_report_summarizes_directory_store_and_bounded_failures() {
    let issuer = key(9);
    let sender = key(1);
    let mut first = directory(&sender, "https://relay-v1.example.test".to_string());
    first.peers.push(PeerDirectoryEntry {
        kernel_id: "did:chio:removed-peer".to_string(),
        public_key: key(44).public_key(),
        endpoint: "https://removed.example.test".to_string(),
        treaty_subscriptions: vec!["treaty:buyer-removed:support-ops".to_string()],
        relay_role: RelayRole::Origin,
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        accepted_ladder_refs: first.peers[0].accepted_ladder_refs.clone(),
        max_batch_frames: 8,
        max_catchup_frames: 16,
        max_catchup_bytes: 64_000,
    });
    let first_bundle = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 1,
        previous_version_sha256: None,
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &first,
        keypair: &issuer,
    })
    .unwrap();
    let trust = PeerDirectoryBundleTrust {
        issuers: vec![TrustedPeerDirectoryIssuer {
            issuer: "did:chio:relay-ops".to_string(),
            key_id: "relay-ops-2026".to_string(),
            public_key: issuer.public_key(),
        }],
        min_version: 1,
        now_unix_ms: NOW,
        profile: RelayProfile::Production,
        limits: RelayProfileLimits::production_defaults(),
    };
    let mut state = PeerDirectoryStateDocument::new("did:chio:buyer-kernel", NOW);
    promote_peer_directory_candidate(&mut state, first_bundle, &trust, NOW).unwrap();
    let active_hash = state.active.as_ref().unwrap().bundle_sha256.clone();

    let mut second = first.clone();
    second
        .peers
        .retain(|peer| peer.kernel_id != "did:chio:removed-peer");
    let broken_candidate = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 2,
        previous_version_sha256: Some("f".repeat(64)),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &second,
        keypair: &issuer,
    })
    .unwrap();
    let _ = promote_peer_directory_candidate(&mut state, broken_candidate, &trust, NOW + 1);
    let continuous = sign_peer_directory_bundle(PeerDirectoryBundleSigningInput {
        issuer: "did:chio:relay-ops",
        key_id: "relay-ops-2026",
        version: 2,
        previous_version_sha256: Some(active_hash),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 60_000,
        directory: &second,
        keypair: &issuer,
    })
    .unwrap();
    promote_peer_directory_candidate(&mut state, continuous, &trust, NOW + 2).unwrap();
    let active = state.active_directory(&trust).unwrap();

    let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
    let retry_id = store
        .enqueue_batch(
            "did:chio:buyer-kernel",
            "did:chio:llamaworks",
            "treaty:buyer-llamaworks:support-ops",
            &sample_batch(),
            NOW - 20_000,
        )
        .unwrap();
    let dead_letter_id = store
        .enqueue_batch(
            "did:chio:buyer-kernel",
            "did:chio:llamaworks",
            "treaty:buyer-llamaworks:support-ops",
            &sample_batch(),
            NOW - 10_000,
        )
        .unwrap();
    store
        .mark_retry(&retry_id, "transport_error", NOW + 1_000)
        .unwrap();
    store
        .mark_dead_letter(&dead_letter_id, "endpoint_denied")
        .unwrap();

    let report = store
        .relay_observability_report(RelayObservabilityInput {
            local_kernel_id: "did:chio:buyer-kernel",
            generated_at_unix_ms: NOW + 3_000,
            peer_directory: Some(&active),
            peer_directory_state: Some(&state),
            profile: RelayProfile::Production,
            recent_failure_limit: 5,
        })
        .unwrap();

    assert_eq!(report.schema, PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA);
    assert!(!report.accepted);
    assert_eq!(report.directory.active_version, Some(2));
    assert_eq!(
        report.directory.removed_peer_ids,
        vec!["did:chio:removed-peer"]
    );
    assert_eq!(report.directory.rejected_candidate_count, 1);
    assert_eq!(
        report.directory.last_rejection_code.as_deref(),
        Some("peer_directory_rollback")
    );
    assert_eq!(report.queue.retry, 1);
    assert_eq!(report.queue.dead_letter, 1);
    assert!(report
        .recent_failures
        .iter()
        .any(|failure| failure.code == "transport_error"));
    assert!(report
        .recommendations
        .iter()
        .any(|recommendation| recommendation.code == "dead_letters_present"));

    let snapshot = store
        .relay_metrics_snapshot("did:chio:buyer-kernel", NOW + 3_000)
        .unwrap();
    assert_eq!(snapshot.schema, PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA);
    let text = snapshot.render(RelayMetricsFormat::Prometheus);
    assert!(text.contains("chio_pheromone_relay_oldest_pending_age_seconds"));
    assert!(text.contains("status=\"retry\""));
    assert!(!text.contains("did:chio:llamaworks"));
}

fn degraded_observability_report() -> RelayObservabilityReport {
    RelayObservabilityReport {
        schema: PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: "degraded".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW,
        directory: chio_pheromone_relay::RelayDirectorySummary {
            active_version: Some(4),
            active_bundle_sha256: Some("a".repeat(64)),
            directory_sha256: Some("b".repeat(64)),
            issuer: Some("did:chio:relay-ops".to_string()),
            expires_at_unix_ms: Some(NOW + 600_000),
            removed_peer_count: 0,
            removed_peer_ids: Vec::new(),
            rejected_candidate_count: 0,
            last_rejection_code: None,
            profile: RelayProfile::Production,
        },
        queue: chio_pheromone_relay::RelayQueueSummary {
            pending: 0,
            retry: 4,
            leased: 0,
            delivered: 12,
            dead_letter: 1,
            oldest_pending_age_ms: Some(300_000),
            stale_lease_count: 0,
            inbox_count: 12,
            cursor_count: 3,
            catchup_event_count: 2,
        },
        recent_failures: vec![chio_pheromone_relay::RelayFailureSummary {
            code: "endpoint_denied".to_string(),
            count: 1,
        }],
        recommendations: vec![
            chio_pheromone_relay::RelayOperatorRecommendation {
                code: "dead_letters_present".to_string(),
                severity: "warning".to_string(),
            },
            chio_pheromone_relay::RelayOperatorRecommendation {
                code: "retries_pending".to_string(),
                severity: "info".to_string(),
            },
            chio_pheromone_relay::RelayOperatorRecommendation {
                code: "endpoint_denied".to_string(),
                severity: "warning".to_string(),
            },
        ],
    }
}

fn alert_profile() -> RelayAlertRoutingProfileDocument {
    RelayAlertRoutingProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        max_source_age_ms: 300_000,
        max_suppression_ms: 3_600_000,
        allowed_label_names: vec![
            "notification_route".to_string(),
            "opsgenie".to_string(),
            "service".to_string(),
            "severity".to_string(),
        ],
        routes: vec![
            RelayAlertRoute {
                route_id: "pagerduty-primary".to_string(),
                kind: RelayAlertRouteKind::PagerDuty,
                notification_route: "pagerduty-primary".to_string(),
                opsgenie: "relay-oncall".to_string(),
                target_ref: "alertmanager:pagerduty-primary".to_string(),
                runbook: "docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage"
                    .to_string(),
            },
            RelayAlertRoute {
                route_id: "ops-digest".to_string(),
                kind: RelayAlertRouteKind::Slack,
                notification_route: "slack-ops-digest".to_string(),
                opsgenie: "relay-oncall".to_string(),
                target_ref: "alertmanager:slack-ops-digest".to_string(),
                runbook: "docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md#stuck-outbox".to_string(),
            },
        ],
        rules: vec![
            RelayAlertRule {
                alert_code: "dead_letters_present".to_string(),
                route_id: "pagerduty-primary".to_string(),
                severity: RelayAlertSeverity::Critical,
                min_window_ms: 300_000,
                unsuppressible: true,
                require_event_evidence: true,
            },
            RelayAlertRule {
                alert_code: "retries_pending".to_string(),
                route_id: "ops-digest".to_string(),
                severity: RelayAlertSeverity::Info,
                min_window_ms: 600_000,
                unsuppressible: false,
                require_event_evidence: false,
            },
            RelayAlertRule {
                alert_code: "endpoint_denied".to_string(),
                route_id: "pagerduty-primary".to_string(),
                severity: RelayAlertSeverity::Critical,
                min_window_ms: 300_000,
                unsuppressible: true,
                require_event_evidence: false,
            },
        ],
    }
}

fn alert_event(code: &str) -> RelayEventReport {
    RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: code.to_string(),
        detail: "relay alert evidence".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW - 30_000,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: Some(code.to_string()),
    }
}

fn handoff_profile() -> RelayAlertHandoffProfileDocument {
    RelayAlertHandoffProfileDocument {
        schema: PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        issued_at_unix_ms: NOW - 1_000,
        expires_at_unix_ms: NOW + 600_000,
        max_alert_report_age_ms: 300_000,
        max_trend_report_age_ms: 900_000,
        receivers: vec![
            RelayAlertHandoffReceiver {
                receiver_id: "alertmanager-pagerduty-primary".to_string(),
                kind: RelayAlertHandoffSinkKind::Alertmanager,
                target_ref: "alertmanager:pagerduty-primary".to_string(),
                notification_route: "pagerduty-primary".to_string(),
                opsgenie: "relay-oncall".to_string(),
                severity_floor: RelayAlertSeverity::Critical,
                escalation_ref: "relay-critical-page".to_string(),
                runbook: "docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md#dead-letter-triage"
                    .to_string(),
            },
            RelayAlertHandoffReceiver {
                receiver_id: "alertmanager-slack-digest".to_string(),
                kind: RelayAlertHandoffSinkKind::Alertmanager,
                target_ref: "alertmanager:slack-ops-digest".to_string(),
                notification_route: "slack-ops-digest".to_string(),
                opsgenie: "relay-oncall".to_string(),
                severity_floor: RelayAlertSeverity::Info,
                escalation_ref: "relay-digest".to_string(),
                runbook: "docs/release/CHIODOS_PHEROMONE_RELAY_RUNBOOK.md#stuck-outbox".to_string(),
            },
        ],
        escalations: vec![
            RelayAlertHandoffEscalation {
                escalation_ref: "relay-critical-page".to_string(),
                severity: RelayAlertSeverity::Critical,
                max_delay_ms: 300_000,
                recommendation_code: "page-primary".to_string(),
            },
            RelayAlertHandoffEscalation {
                escalation_ref: "relay-digest".to_string(),
                severity: RelayAlertSeverity::Info,
                max_delay_ms: 3_600_000,
                recommendation_code: "ops-digest".to_string(),
            },
        ],
    }
}

#[test]
fn relay_alert_evaluation_routes_degraded_observability_with_bounded_evidence() {
    let observability = degraded_observability_report();
    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let event = RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: "dead_letters_present".to_string(),
        detail: "dead-lettered relay batch".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW - 30_000,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: Some("dead_letters_present".to_string()),
    };
    let report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[event],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();

    assert_eq!(report.schema, PHEROMONE_RELAY_ALERT_REPORT_SCHEMA);
    assert!(!report.accepted);
    assert_eq!(report.alerts.len(), 3);
    let critical = report
        .alerts
        .iter()
        .find(|alert| alert.code == "dead_letters_present")
        .unwrap();
    assert_eq!(critical.state, "firing");
    assert_eq!(critical.severity, "critical");
    assert_eq!(critical.notification_route, "pagerduty-primary");
    assert_eq!(critical.opsgenie, "relay-oncall");
    assert_eq!(critical.event_evidence_sha256.len(), 1);
    assert!(critical.labels.keys().all(|key| {
        matches!(
            key.as_str(),
            "notification_route" | "opsgenie" | "service" | "severity"
        )
    }));
}

#[test]
fn relay_alert_evaluation_rejects_secrets_dynamic_urls_and_bad_suppression() {
    let mut profile = alert_profile();
    profile.routes[0].target_ref = "https://hooks.example.test/secret-token".to_string();
    let err = relay_alert_routing_profile_from_json(&serde_json::to_string(&profile).unwrap(), NOW)
        .unwrap_err();
    assert_eq!(err.code(), "alert_routing_invalid");

    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let suppression = RelayAlertSuppressionStateDocument {
        schema: PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        entries: vec![RelayAlertSuppressionEntry {
            alert_code: "dead_letters_present".to_string(),
            route_id: "pagerduty-primary".to_string(),
            reason: "operator_acknowledged".to_string(),
            starts_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 120_000,
        }],
    };
    let suppression = relay_alert_suppression_state_from_json(
        &serde_json::to_string(&suppression).unwrap(),
        &profile,
    )
    .unwrap();
    let observability = degraded_observability_report();
    let event = RelayEventReport {
        schema: chio_pheromone_relay::PHEROMONE_RELAY_EVENT_REPORT_SCHEMA.to_string(),
        accepted: false,
        code: "dead_letters_present".to_string(),
        detail: "dead-lettered relay batch".to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        generated_at_unix_ms: NOW,
        event_kind: "outbound_delivery".to_string(),
        stable_failure_code: Some("dead_letters_present".to_string()),
    };
    let report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: Some(&suppression),
        event_reports: &[event],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();
    let critical = report
        .alerts
        .iter()
        .find(|alert| alert.code == "dead_letters_present")
        .unwrap();
    assert_eq!(critical.state, "firing");
    assert_eq!(critical.suppressed_until_unix_ms, None);

    let overlong = RelayAlertSuppressionStateDocument {
        schema: PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA.to_string(),
        local_kernel_id: "did:chio:buyer-kernel".to_string(),
        entries: vec![RelayAlertSuppressionEntry {
            alert_code: "retries_pending".to_string(),
            route_id: "ops-digest".to_string(),
            reason: "maintenance".to_string(),
            starts_at_unix_ms: NOW,
            expires_at_unix_ms: NOW + 3_600_001,
        }],
    };
    let err = relay_alert_suppression_state_from_json(
        &serde_json::to_string(&overlong).unwrap(),
        &profile,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_routing_invalid");

    let mut false_clear = degraded_observability_report();
    false_clear.recommendations.clear();
    let err = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &false_clear,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let err = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let err = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &observability,
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &[],
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: Some("0"),
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");
}

#[test]
fn relay_alert_handoff_dry_run_proves_routeable_artifacts_without_delivery() {
    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let events = vec![alert_event("dead_letters_present")];
    let alert_report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &degraded_observability_report(),
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &events,
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();
    let trend_report = generate_relay_trend_report(RelayTrendInput {
        local_kernel_id: "did:chio:buyer-kernel",
        observability_reports: &[degraded_observability_report()],
        event_reports: &events,
        routing_profile: &profile,
        since_unix_ms: NOW - 60_000,
        until_unix_ms: NOW + 60_000,
    })
    .unwrap();
    let handoff = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&handoff_profile()).unwrap(),
        NOW,
    )
    .unwrap();

    let report = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap();

    assert_eq!(report.schema, PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA);
    assert!(report.accepted);
    assert_eq!(report.code, "accepted");
    assert_eq!(report.firing_alert_count, 3);
    assert_eq!(report.critical_firing_count, 2);
    assert_eq!(report.source_alert_report_sha256.len(), 64);
    assert_eq!(report.source_trend_report_sha256.len(), 64);
    assert!(report.routes.iter().any(|route| {
        route.target_ref == "alertmanager:pagerduty-primary"
            && route.highest_severity == RelayAlertSeverity::Critical
            && route
                .alert_codes
                .contains(&"dead_letters_present".to_string())
    }));
}

#[test]
fn relay_alert_handoff_rejects_secret_dynamic_and_uncovered_targets() {
    let mut bad_profile = handoff_profile();
    bad_profile.receivers[0].target_ref = "https://hooks.example.test/secret-token".to_string();
    let err =
        relay_alert_handoff_profile_from_json(&serde_json::to_string(&bad_profile).unwrap(), NOW)
            .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut bearer_profile = handoff_profile();
    bearer_profile.receivers[0].target_ref = "alertmanager:bearer-prod".to_string();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&bearer_profile).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let profile = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&alert_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let events = vec![alert_event("dead_letters_present")];
    let alert_report = evaluate_relay_alerts(RelayAlertEvaluationInput {
        observability: &degraded_observability_report(),
        routing_profile: &profile,
        suppression_state: None,
        event_reports: &events,
        now_unix_ms: NOW + 60_000,
        expected_source_report_sha256: None,
    })
    .unwrap();
    let trend_report = generate_relay_trend_report(RelayTrendInput {
        local_kernel_id: "did:chio:buyer-kernel",
        observability_reports: &[degraded_observability_report()],
        event_reports: &events,
        routing_profile: &profile,
        since_unix_ms: NOW - 60_000,
        until_unix_ms: NOW + 60_000,
    })
    .unwrap();

    let mut missing_receiver = handoff_profile();
    missing_receiver
        .receivers
        .retain(|receiver| receiver.target_ref != "alertmanager:pagerduty-primary");
    let missing_receiver = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&missing_receiver).unwrap(),
        NOW,
    )
    .unwrap();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &missing_receiver,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut stale_alert = alert_report.clone();
    stale_alert.generated_at_unix_ms = NOW - 600_000;
    let handoff = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&handoff_profile()).unwrap(),
        NOW,
    )
    .unwrap();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &stale_alert,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut stale_trend = trend_report.clone();
    stale_trend.until_unix_ms = NOW - 1_000_000;
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &stale_trend,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut mismatched_source = alert_report.clone();
    mismatched_source.alerts[0].source_report_sha256 = "c".repeat(64);
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &mismatched_source,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut invalid_source_hash = alert_report.clone();
    invalid_source_hash.source_report_sha256 = "not-a-hash".to_string();
    for alert in &mut invalid_source_hash.alerts {
        alert.source_report_sha256 = "not-a-hash".to_string();
    }
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &invalid_source_hash,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut hidden_critical = alert_report.clone();
    hidden_critical.alerts[0].state = "suppressed".to_string();
    hidden_critical.alerts[0].suppressed_until_unix_ms = Some(NOW + 120_000);
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &hidden_critical,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut missing_event = alert_report.clone();
    missing_event.alerts[0].event_evidence_sha256.clear();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &missing_event,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut bad_runbook = alert_report.clone();
    bad_runbook.alerts[0].runbook = "docs/release/other-runbook.md".to_string();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &bad_runbook,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut unknown_alert_code = alert_report.clone();
    unknown_alert_code.alerts[0].code = "bounded_unknown".to_string();
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &unknown_alert_code,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut missing_trend_code = trend_report.clone();
    missing_trend_code
        .points
        .retain(|point| point.code != alert_report.alerts[0].code);
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &alert_report,
        trend_report: &missing_trend_code,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut unbounded_label = alert_report.clone();
    unbounded_label.alerts[0]
        .labels
        .insert("peer_id".to_string(), "did:chio:vendor-a".to_string());
    let err = evaluate_relay_alert_handoff(RelayAlertHandoffInput {
        alert_report: &unbounded_label,
        trend_report: &trend_report,
        routing_profile: &profile,
        handoff_profile: &handoff,
        now_unix_ms: NOW + 60_000,
    })
    .unwrap_err();
    assert_eq!(err.code(), "alert_source_invalid");

    let mut unknown_sink = handoff_profile();
    unknown_sink.receivers[0].kind = RelayAlertHandoffSinkKind::Unknown;
    let err =
        relay_alert_handoff_profile_from_json(&serde_json::to_string(&unknown_sink).unwrap(), NOW)
            .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut weak_escalation = handoff_profile();
    weak_escalation.receivers[0].escalation_ref = "relay-digest".to_string();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&weak_escalation).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut duplicate_route = handoff_profile();
    duplicate_route.receivers[1].target_ref = "alertmanager:secondary".to_string();
    duplicate_route.receivers[1].notification_route =
        duplicate_route.receivers[0].notification_route.clone();
    duplicate_route.receivers[1].opsgenie = duplicate_route.receivers[0].opsgenie.clone();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&duplicate_route).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut missing_runbook = handoff_profile();
    missing_runbook.receivers[0].runbook.clear();
    let err = relay_alert_handoff_profile_from_json(
        &serde_json::to_string(&missing_runbook).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_handoff_invalid");

    let mut route_collision = alert_profile();
    let mut duplicate = route_collision.routes[0].clone();
    duplicate.route_id = "pagerduty-primary-copy".to_string();
    route_collision.routes.push(duplicate);
    let err = relay_alert_routing_profile_from_json(
        &serde_json::to_string(&route_collision).unwrap(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "alert_routing_invalid");
}

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
