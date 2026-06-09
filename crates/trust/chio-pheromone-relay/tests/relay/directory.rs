use super::common::{
    accepted_report, directory, json, key, promote_peer_directory_candidate, sample_batch,
    sign_peer_directory_bundle, sign_relay_http_request, PeerDirectory,
    PeerDirectoryBundleSigningInput, PeerDirectoryBundleTrust, PeerDirectoryEntry,
    PeerDirectoryStateDocument, PheromoneGossipBatch, RelayHttpSigningInput,
    RelayHttpVerificationContext, RelayNonceRecorder, RelayNonceSet, RelayProfile,
    RelayProfileLimits, RelayRole, SqlitePheromoneRelayStore, TrustedPeerDirectoryIssuer, NOW,
    PHEROMONE_BATCH_RELAY_PATH,
};

#[test]
fn peer_directory_rejects_duplicate_peer_ids() {
    let sender = key(1);
    let mut document = directory(&sender, "http://127.0.0.1:18080".to_string());
    document.peers.push(document.peers[0].clone());

    let err = PeerDirectory::from_document(document, NOW).unwrap_err();

    assert_eq!(err.code(), "duplicate_peer");
}

#[test]
fn peer_directory_rejects_padded_peer_kernel_ids() {
    let sender = key(1);
    let mut document = directory(&sender, "http://127.0.0.1:18080".to_string());
    document.peers[0].kernel_id = " did:chio:llamaworks".to_string();

    let err = PeerDirectory::from_document(document, NOW).unwrap_err();

    assert_eq!(err.code(), "unknown_peer");
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

    let mut wedged = directory(&sender, "http://127.0.0.1:18080".to_string());
    wedged.peers[0].max_batch_frames = 4;
    wedged.peers[0].max_catchup_frames = 2;
    let catchup_wedge =
        PeerDirectory::from_document_with_profile(wedged, NOW, RelayProfile::LocalDev, &limits)
            .unwrap_err();
    assert_eq!(catchup_wedge.code(), "relay_profile_denied");
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
fn relay_store_catchup_limit_counts_frames_not_batches() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRelayStore::open(temp.path().join("relay.sqlite3")).unwrap();
    let mut first = sample_batch();
    first.frames.push(first.frames[0].clone());
    let mut second = sample_batch();
    second.frames.push(second.frames[0].clone());

    store
        .enqueue_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &first.treaty_id,
            &first,
            NOW,
        )
        .unwrap();
    store
        .enqueue_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &second.treaty_id,
            &second,
            NOW + 1,
        )
        .unwrap();

    let (catchup_frames, next_cursor) = store
        .catchup_batches("did:chio:buyer-kernel", &first.treaty_id, "0", 3, 256_000)
        .unwrap();

    assert_eq!(catchup_frames, vec![first.clone()]);
    assert_ne!(next_cursor, "0");

    let (remaining_frames, _) = store
        .catchup_batches(
            "did:chio:buyer-kernel",
            &first.treaty_id,
            &next_cursor,
            3,
            256_000,
        )
        .unwrap();
    assert_eq!(remaining_frames, vec![second]);
}

#[test]
fn relay_store_catchup_denies_first_batch_above_frame_limit() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqlitePheromoneRelayStore::open(temp.path().join("relay.sqlite3")).unwrap();
    let mut batch = sample_batch();
    batch.frames.push(batch.frames[0].clone());

    store
        .enqueue_batch(
            "did:chio:llamaworks",
            "did:chio:buyer-kernel",
            &batch.treaty_id,
            &batch,
            NOW,
        )
        .unwrap();

    let error = store
        .catchup_batches("did:chio:buyer-kernel", &batch.treaty_id, "0", 1, 256_000)
        .unwrap_err();

    assert_eq!(error.code(), "catchup_denied");
    assert!(error
        .to_string()
        .contains("catch-up frame limit exceeded before first batch"));
}
