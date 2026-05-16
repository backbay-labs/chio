use super::*;

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
