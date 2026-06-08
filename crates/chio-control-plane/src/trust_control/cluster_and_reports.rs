mod cluster_and_reports_tests {
    use super::super::cluster::*;
    use super::super::report_rendering::*;
    use super::super::report_validation::*;
    use super::super::*;
    use axum::body::to_bytes;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::path::PathBuf;

    use chio_test_support::prelude::*;

    fn base_config() -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().test_unwrap(),
            service_token: "token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: 300,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
        }
    }

    fn state_with_cluster(
        advertise_url: &str,
        peer_urls: &[&str],
        receipt_db_path: Option<PathBuf>,
        revocation_db_path: Option<PathBuf>,
        budget_db_path: Option<PathBuf>,
    ) -> TrustServiceState {
        let mut config = base_config();
        config.advertise_url = Some(advertise_url.to_string());
        config.peer_urls = peer_urls.iter().map(|value| value.to_string()).collect();
        config.receipt_db_path = receipt_db_path;
        config.revocation_db_path = revocation_db_path;
        config.budget_db_path = budget_db_path;
        let cluster = build_cluster_state(&config, config.listen).test_unwrap();
        TrustServiceState {
            config,
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            cluster,
        }
    }

    fn unique_temp_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }

    fn sample_tool_receipt(id: &str, capability_id: &str) -> ChioReceipt {
        let keypair = Keypair::generate();
        let parameters = json!({"message": "cluster"});
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp: 11,
                capability_id: capability_id.to_string(),
                tool_server: "wrapped-http-mock".to_string(),
                tool_name: "echo_json".to_string(),
                action: ToolCallAction::from_parameters(parameters).test_unwrap(),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .test_unwrap()
    }

    fn sample_child_receipt(id: &str, suffix: &str) -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            chio_core::receipt::lineage::ChildRequestReceiptBody {
                id: id.to_string(),
                timestamp: 13,
                session_id: chio_core::session::SessionId::new(format!("sess-{suffix}")),
                parent_request_id: chio_core::session::RequestId::new(format!("parent-{suffix}")),
                request_id: chio_core::session::RequestId::new(format!("child-{suffix}")),
                operation_kind: chio_core::session::OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: "outcome-hash".to_string(),
                policy_hash: "policy-hash".to_string(),
                metadata: Some(json!({ "source": "cluster-test" })),
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .test_unwrap()
    }

    fn sample_capability(id: &str) -> CapabilityToken {
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope::default(),
                issued_at: 1_000,
                expires_at: 9_000,
                delegation_chain: vec![],
            },
            &issuer,
        )
        .test_unwrap()
    }

    #[test]
    fn build_cluster_state_validates_inputs_and_normalizes_peers() {
        let mut invalid = base_config();
        invalid.advertise_url = Some("http://127.0.0.1:3200".to_string());
        invalid.peer_urls = vec!["http://127.0.0.1:3300".to_string()];
        invalid.authority_seed_path = Some(unique_temp_path("authority", "seed"));

        let error = build_cluster_state(&invalid, invalid.listen).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("--authority-db instead of --authority-seed-file"));

        assert!(
            build_cluster_state(&base_config(), "127.0.0.1:0".parse().test_unwrap())
                .test_unwrap()
                .is_none()
        );

        let mut standalone_advertised = base_config();
        standalone_advertised.allow_local_peer_urls = false;
        standalone_advertised.advertise_url = Some("http://127.0.0.1:3200/".to_string());
        assert!(
            build_cluster_state(&standalone_advertised, standalone_advertised.listen)
                .test_unwrap()
                .is_none()
        );

        let mut config = base_config();
        config.advertise_url = Some("http://127.0.0.1:3200/".to_string());
        config.peer_urls = vec![
            "http://127.0.0.1:3200/".to_string(),
            " http://127.0.0.1:3300/ ".to_string(),
            "http://127.0.0.1:3300".to_string(),
        ];

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.self_url, "http://127.0.0.1:3200");
        assert_eq!(guard.peers.len(), 1);
        assert!(guard.peers.contains_key("http://127.0.0.1:3300"));
    }

    #[test]
    fn cluster_peer_url_validation_rejects_local_networks_by_default() {
        let error = normalize_cluster_config_url("http://127.0.0.1:3300", false).test_unwrap_err();
        assert!(error.to_string().contains("--allow-local-peer-urls"));

        let normalized =
            normalize_cluster_config_url(" http://127.0.0.1:3300/ ", true).test_unwrap();
        assert_eq!(normalized, "http://127.0.0.1:3300");
    }

    #[test]
    fn cluster_peer_url_validation_rejects_ambient_authority_material() {
        for peer_url in [
            "https://user:pass@control.example.test:443",
            "http://127.0.0.1:3300?token=secret",
            "http://127.0.0.1:3300#fragment",
        ] {
            let error = normalize_cluster_config_url(peer_url, true).test_unwrap_err();
            assert!(
                error.to_string().contains("cluster URL"),
                "unexpected error for peer URL `{peer_url}`: {error}",
            );
        }
    }

    #[test]
    fn compute_cluster_consensus_tracks_role_quorum_and_election_terms() {
        let mut cluster = ClusterRuntimeState {
            self_url: "http://node-a".to_string(),
            peers: HashMap::from([
                ("http://node-b".to_string(), PeerSyncState::default()),
                ("http://node-c".to_string(), PeerSyncState::default()),
            ]),
            election_term: 0,
            last_leader_url: None,
            term_started_at: None,
            lease_expires_at: None,
            lease_ttl_ms: authority_lease_ttl(Duration::from_millis(25)).as_millis() as u64,
        };

        let initial = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(initial.role, "candidate");
        assert!(!initial.has_quorum);
        assert_eq!(initial.quorum_size, 2);
        assert_eq!(initial.reachable_nodes, 1);
        assert_eq!(initial.election_term, 0);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &initial).is_none());

        cluster.peers.get_mut("http://node-b").test_unwrap().health = PeerHealth::Healthy;
        cluster
            .peers
            .get_mut("http://node-b")
            .test_unwrap()
            .last_contact_at = Some(unix_timestamp_now());
        let with_quorum = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(with_quorum.role, "leader");
        assert!(with_quorum.has_quorum);
        assert_eq!(with_quorum.leader_url.as_deref(), Some("http://node-a"));
        assert_eq!(with_quorum.reachable_nodes, 2);
        assert_eq!(with_quorum.election_term, 1);
        let with_quorum_lease =
            cluster_authority_lease_view_locked(&mut cluster, &with_quorum).test_unwrap();
        assert_eq!(with_quorum_lease.lease_epoch, 1);
        assert!(with_quorum_lease.lease_id.contains("http://node-a"));
        assert!(with_quorum_lease.lease_expires_at >= unix_timestamp_now());

        cluster.peers.get_mut("http://node-c").test_unwrap().health = PeerHealth::Healthy;
        cluster
            .peers
            .get_mut("http://node-c")
            .test_unwrap()
            .last_contact_at = Some(unix_timestamp_now());
        let stable = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(stable.role, "leader");
        assert_eq!(stable.election_term, 1);
        assert_eq!(stable.reachable_nodes, 3);

        cluster.peers.get_mut("http://node-b").test_unwrap().health = PeerHealth::Unhealthy;
        cluster.peers.get_mut("http://node-c").test_unwrap().health = PeerHealth::Unhealthy;
        let lost_quorum = compute_cluster_consensus_locked(&mut cluster);
        assert_eq!(lost_quorum.role, "candidate");
        assert!(!lost_quorum.has_quorum);
        assert_eq!(lost_quorum.election_term, 2);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &lost_quorum).is_none());
    }

    #[test]
    fn compute_cluster_consensus_drops_stale_peers_after_authority_lease_timeout() {
        let mut cluster = ClusterRuntimeState {
            self_url: "http://node-a".to_string(),
            peers: HashMap::from([(
                "http://node-b".to_string(),
                PeerSyncState {
                    health: PeerHealth::Healthy,
                    last_contact_at: Some(unix_timestamp_now().saturating_sub(5)),
                    ..PeerSyncState::default()
                },
            )]),
            election_term: 0,
            last_leader_url: None,
            term_started_at: None,
            lease_expires_at: None,
            lease_ttl_ms: authority_lease_ttl(Duration::from_millis(25)).as_millis() as u64,
        };

        let consensus = compute_cluster_consensus_locked(&mut cluster);
        assert!(!consensus.has_quorum);
        assert_eq!(consensus.reachable_nodes, 1);
        assert!(cluster_authority_lease_view_locked(&mut cluster, &consensus).is_none());
    }

    #[tokio::test]
    async fn leader_visibility_responses_add_cluster_metadata_and_reject_scalars() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        update_peer_reachable(&state, "http://node-b");

        let response = json_response_with_leader_visibility(&state, json!({ "stored": true }));
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .test_unwrap();
        let body: Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(body["stored"], Value::Bool(true));
        assert_eq!(
            body["handledBy"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(
            body["leaderUrl"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["visibleAtLeader"], Value::Bool(true));
        assert_eq!(
            body["clusterAuthority"]["authorityId"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["clusterAuthority"]["term"], Value::from(1));
        assert_eq!(body["clusterAuthority"]["leaseValid"], Value::Bool(true));

        let scalar = json_response_with_leader_visibility(&state, "not-an-object");
        assert_eq!(scalar.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(scalar.into_body(), usize::MAX).await.test_unwrap();
        let text = String::from_utf8(body.to_vec()).test_unwrap();
        assert!(text.contains("success responses must be JSON objects"));
    }

    #[tokio::test]
    async fn budget_quorum_commit_metadata_tracks_quorum_witnesses() {
        let state = state_with_cluster(
            "http://node-a",
            &["http://node-b", "http://node-c"],
            None,
            None,
            None,
        );
        update_peer_reachable(&state, "http://node-b");
        update_peer_reachable(&state, "http://node-c");
        update_peer_budget_cursor(
            &state,
            "http://node-b",
            BudgetCursor {
                seq: 9,
                updated_at: 14,
                capability_id: "cap-1".to_string(),
                grant_index: 0,
            },
        );
        update_peer_budget_cursor(
            &state,
            "http://node-c",
            BudgetCursor {
                seq: 7,
                updated_at: 12,
                capability_id: "cap-1".to_string(),
                grant_index: 0,
            },
        );

        let commit = budget_write_quorum_commit_view(&state, 8).test_unwrap();
        assert!(commit.quorum_committed);
        assert_eq!(commit.quorum_size, 2);
        assert_eq!(commit.committed_nodes, 2);
        assert_eq!(
            commit.witness_urls,
            vec!["http://node-a".to_string(), "http://node-b".to_string()]
        );

        let response = json_response_with_leader_visibility_and_budget_commit(
            &state,
            json!({ "allowed": true }),
            Some(commit),
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .test_unwrap();
        let body: Value = serde_json::from_slice(&body).test_unwrap();
        assert_eq!(body["budgetCommit"]["budgetSeq"], Value::from(8));
        assert_eq!(body["budgetCommit"]["commitIndex"], Value::from(8));
        assert_eq!(body["budgetCommit"]["quorumCommitted"], Value::Bool(true));
        assert_eq!(body["budgetCommit"]["committedNodes"], Value::from(2));
        assert_eq!(
            body["budgetCommit"]["authorityId"],
            Value::String("http://node-a".to_string())
        );
        assert_eq!(body["budgetCommit"]["budgetTerm"], Value::from(1));
        assert_eq!(
            body["budgetCommit"]["witnessUrls"],
            json!(["http://node-a", "http://node-b"])
        );
    }

    #[test]
    fn peer_state_helpers_update_health_cursors_and_snapshot_thresholds() {
        let state = state_with_cluster("http://node-a", &["http://node-b"], None, None, None);

        update_peer_reachable(&state, "http://node-b");
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("healthy")
        );

        update_peer_sync_error(&state, "http://node-b", "lagging".to_string());
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.last_error.clone()),
            Some(Some("lagging".to_string()))
        );

        update_peer_failure(&state, "http://node-b", "offline".to_string());
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("unhealthy")
        );
        assert!(peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_success(&state, "http://node-b");
        assert_eq!(
            with_peer_state(&state, "http://node-b", |peer| peer.health.label()),
            Some("healthy")
        );
        assert!(!peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_revocation_cursor(
            &state,
            "http://node-b",
            RevocationCursor {
                revoked_at: 5,
                capability_id: "cap-1".to_string(),
            },
        );
        update_peer_budget_cursor(
            &state,
            "http://node-b",
            BudgetCursor {
                seq: 8,
                updated_at: 13,
                capability_id: "cap-1".to_string(),
                grant_index: 2,
            },
        );
        update_peer_tool_seq(&state, "http://node-b", 3);
        update_peer_child_seq(&state, "http://node-b", 4);
        update_peer_lineage_seq(&state, "http://node-b", 5);
        update_peer_delta_records(
            &state,
            "http://node-b",
            CLUSTER_SNAPSHOT_RECORD_THRESHOLD - 1,
        );
        assert_eq!(peer_tool_seq(&state, "http://node-b"), 3);
        assert_eq!(peer_child_seq(&state, "http://node-b"), 4);
        assert_eq!(peer_lineage_seq(&state, "http://node-b"), 5);
        assert_eq!(
            peer_revocation_cursor(&state, "http://node-b")
                .test_unwrap()
                .capability_id,
            "cap-1"
        );
        assert_eq!(
            peer_budget_cursor(&state, "http://node-b")
                .test_unwrap()
                .grant_index,
            2
        );
        assert!(!peer_should_force_snapshot(&state, "http://node-b"));

        update_peer_delta_records(&state, "http://node-b", 1);
        assert!(peer_should_force_snapshot(&state, "http://node-b"));

        assert!(budget_visibility_matches(true, Some(1), Some(2)));
        assert!(!budget_visibility_matches(true, None, Some(2)));
        assert!(budget_visibility_matches(false, Some(2), Some(2)));
        assert!(budget_visibility_matches(false, Some(1), None));
        assert!(!budget_visibility_matches(false, None, Some(3)));
    }

    #[test]
    fn auth_helpers_and_metered_billing_validation_cover_error_paths() {
        let mut headers = HeaderMap::new();
        let auth_error = bearer_token_from_headers(&headers).test_unwrap_err();
        assert_eq!(auth_error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            auth_error
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"chio-passport-issuance\"")
        );

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer issue-token"),
        );
        assert_eq!(
            bearer_token_from_headers(&headers).test_unwrap(),
            "issue-token"
        );
        assert!(validate_service_auth(&headers, "issue-token").is_ok());
        assert_eq!(
            validate_service_auth(&headers, "")
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let mut config = base_config();
        // The admin bearer header carries "issue-token"; align the configured
        // service token so the admin principal resolves and the downstream
        // tenant-token-equals-service-token collision check exercises a real
        // conflict rather than failing the bearer match first.
        config.service_token = "issue-token".to_string();
        config
            .tenant_read_tokens
            .insert("tenant-a".to_string(), "tenant-read-token".to_string());
        let admin_principal = resolve_control_read_principal(&headers, &config).test_unwrap();
        assert_eq!(admin_principal, ResolvedControlReadPrincipal::AdminService);
        config
            .tenant_read_tokens
            .insert("tenant-collision".to_string(), "issue-token".to_string());
        assert_eq!(
            resolve_control_read_principal(&headers, &config)
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        config.tenant_read_tokens.remove("tenant-collision");

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer tenant-read-token"),
        );
        let tenant_principal = resolve_control_read_principal(&headers, &config).test_unwrap();
        assert_eq!(
            tenant_principal,
            ResolvedControlReadPrincipal::TenantRead {
                tenant_id: "tenant-a".to_string()
            }
        );
        assert!(validate_service_auth(&headers, "issue-token").is_err());
        assert!(tenant_principal
            .authorize_evidence_export_query(EvidenceExportQuery::admin_all())
            .is_err());
        let tenant_export = tenant_principal
            .authorize_evidence_export_query(EvidenceExportQuery::default())
            .test_unwrap();
        assert_eq!(tenant_export.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(
            tenant_export.read_boundary,
            Some(ReceiptReadBoundary::TenantScoped {
                tenant: "tenant-a".to_string()
            })
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer issue-token"),
        );
        let invalid_auth = validate_service_auth(&headers, "other-token").test_unwrap_err();
        assert_eq!(invalid_auth.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            invalid_auth
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );

        let cluster_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let issued_at = unix_timestamp_now() as i64;
        let signature = cluster_peer_auth_signature(
            &cluster_state.config.service_token,
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
            issued_at,
            None,
        )
        .test_unwrap();
        headers.clear();
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
        let peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap();
        assert_eq!(peer.node_id, "http://node-b");

        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_static("deadbeef"),
        );
        let invalid_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(invalid_peer.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));

        let expired_issued_at = issued_at - CLUSTER_AUTH_MAX_SKEW_SECS - 1;
        let expired_signature = cluster_peer_auth_signature(
            &cluster_state.config.service_token,
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
            expired_issued_at,
            None,
        )
        .test_unwrap();
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&expired_issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&expired_signature).test_unwrap(),
        );
        let expired_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(expired_peer.status(), StatusCode::UNAUTHORIZED);
        clear_cluster_peer_auth_failures("http://node-b");

        for attempt in 0..CLUSTER_AUTH_FAILURE_BURST {
            let invalid_issued_at = issued_at + attempt as i64;
            headers.insert(
                CLUSTER_AUTH_ISSUED_AT_HEADER,
                HeaderValue::from_str(&invalid_issued_at.to_string()).test_unwrap(),
            );
            headers.insert(
                CLUSTER_AUTH_SIGNATURE_HEADER,
                HeaderValue::from_str(&format!("deadbeef-{attempt}")).test_unwrap(),
            );
            let response = validate_cluster_peer_auth(
                &headers,
                &cluster_state.config,
                INTERNAL_CLUSTER_STATUS_PATH,
            )
            .test_unwrap_err();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let limited_issued_at = issued_at + CLUSTER_AUTH_FAILURE_BURST as i64;
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&limited_issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_static("deadbeef-final"),
        );
        let limited_peer = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap_err();
        assert_eq!(limited_peer.status(), StatusCode::TOO_MANY_REQUESTS);
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).test_unwrap(),
        );
        let peer_after_spoofed_failures = validate_cluster_peer_auth(
            &headers,
            &cluster_state.config,
            INTERNAL_CLUSTER_STATUS_PATH,
        )
        .test_unwrap();
        assert_eq!(peer_after_spoofed_failures.node_id, "http://node-b");
        clear_cluster_peer_auth_failures(&cluster_peer_auth_unverified_failure_key(
            "http://node-b",
            INTERNAL_CLUSTER_STATUS_PATH,
        ));
        clear_cluster_peer_auth_failures("http://node-b");

        let mut request = MeteredBillingReconciliationUpdateRequest {
            receipt_id: "receipt-1".to_string(),
            adapter_kind: "usage-adapter".to_string(),
            evidence_id: "evidence-1".to_string(),
            observed_units: 3,
            billed_cost: MonetaryAmount {
                units: 25,
                currency: "USD".to_string(),
            },
            evidence_sha256: Some("digest".to_string()),
            recorded_at: 44,
            reconciliation_state: MeteredBillingReconciliationState::Open,
            note: None,
        };
        assert!(validate_metered_billing_reconciliation_request(&request).is_ok());

        request.receipt_id.clear();
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("receiptId must not be empty".to_string())
        );
        request.receipt_id = "receipt-1".to_string();
        request.observed_units = 0;
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("observedUnits must be greater than zero".to_string())
        );
        request.observed_units = 3;
        request.billed_cost.currency.clear();
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("billedCost.currency must not be empty".to_string())
        );
        request.billed_cost.currency = "USD".to_string();
        request.evidence_sha256 = Some(String::new());
        assert_eq!(
            validate_metered_billing_reconciliation_request(&request),
            Err("evidenceSha256 must not be empty when provided".to_string())
        );
    }

    #[test]
    fn trust_service_config_boundary_rejects_invalid_auth_material_and_cluster_timing() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));

        let mut blank_tenant_id = base_config();
        blank_tenant_id
            .tenant_read_tokens
            .insert(" ".to_string(), "tenant-read-token".to_string());
        assert_eq!(
            resolve_control_read_principal(&headers, &blank_tenant_id)
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let mut blank_tenant_token = base_config();
        blank_tenant_token
            .tenant_read_tokens
            .insert("tenant-a".to_string(), "   ".to_string());
        assert_eq!(
            resolve_control_read_principal(&headers, &blank_tenant_token)
                .test_unwrap_err()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let mut zero_cluster_interval = base_config();
        zero_cluster_interval.advertise_url = Some("http://127.0.0.1:3200".to_string());
        zero_cluster_interval.peer_urls = vec!["http://127.0.0.1:3300".to_string()];
        zero_cluster_interval.cluster_sync_interval = Duration::ZERO;
        let error = build_cluster_state(&zero_cluster_interval, zero_cluster_interval.listen)
            .test_unwrap_err();
        assert!(error
            .to_string()
            .contains("cluster sync interval must be non-zero"));
    }

    #[test]
    fn cluster_snapshot_round_trip_copies_receipts_revocations_lineage_and_budgets() {
        let source_receipt_db = unique_temp_path("cluster-source-receipts", "sqlite3");
        let source_revocation_db = unique_temp_path("cluster-source-revocations", "sqlite3");
        let source_budget_db = unique_temp_path("cluster-source-budgets", "sqlite3");
        let target_receipt_db = unique_temp_path("cluster-target-receipts", "sqlite3");
        let target_revocation_db = unique_temp_path("cluster-target-revocations", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budgets", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            Some(source_receipt_db.clone()),
            Some(source_revocation_db.clone()),
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            Some(target_receipt_db.clone()),
            Some(target_revocation_db.clone()),
            Some(target_budget_db.clone()),
        );

        {
            let revocation_store = SqliteRevocationStore::open(&source_revocation_db).test_unwrap();
            revocation_store
                .upsert_revocation(&RevocationRecord {
                    capability_id: "cap-1".to_string(),
                    revoked_at: 17,
                })
                .test_unwrap();
        }
        {
            let receipt_store = SqliteReceiptStore::open(&source_receipt_db).test_unwrap();
            receipt_store
                .append_chio_receipt(&sample_tool_receipt("tool-1", "cap-1"))
                .test_unwrap();
            receipt_store
                .append_child_receipt(&sample_child_receipt("child-1", "alpha"))
                .test_unwrap();
            receipt_store
                .record_capability_snapshot(&sample_capability("cap-1"), None)
                .test_unwrap();
        }
        {
            let budget_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            budget_store
                .try_charge_cost_with_ids(
                    "cap-1",
                    0,
                    Some(4),
                    9,
                    Some(9),
                    Some(32),
                    Some("hold-1"),
                    Some("hold-1:authorize"),
                )
                .test_unwrap();
            budget_store
                .reduce_charge_cost_with_ids("cap-1", 0, 4, Some("hold-1"), Some("hold-1:release"))
                .test_unwrap();
        }

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.replication.tool_seq, 1);
        assert_eq!(snapshot.replication.child_seq, 1);
        assert_eq!(snapshot.replication.lineage_seq, 1);
        assert_eq!(snapshot.replication.budget_seq, 2);
        assert_eq!(snapshot.budget_mutation_events.len(), 2);
        assert_eq!(
            snapshot
                .budget_mutation_events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["hold-1:authorize", "hold-1:release"]
        );
        assert_eq!(
            snapshot
                .replication
                .revocation_cursor
                .as_ref()
                .test_unwrap()
                .capability_id,
            "cap-1"
        );

        let generated_at = snapshot.generated_at;
        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let revocations = SqliteRevocationStore::open(&target_revocation_db)
            .test_unwrap()
            .list_revocations_after(MAX_LIST_LIMIT, None, None)
            .test_unwrap();
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].capability_id, "cap-1");

        let receipt_store = SqliteReceiptStore::open(&target_receipt_db).test_unwrap();
        assert_eq!(
            receipt_store
                .list_tool_receipts_after_seq(0, MAX_LIST_LIMIT)
                .test_unwrap()
                .len(),
            1
        );
        assert_eq!(
            receipt_store
                .list_child_receipts_after_seq(0, MAX_LIST_LIMIT)
                .test_unwrap()
                .len(),
            1
        );
        assert_eq!(
            receipt_store
                .list_capability_snapshots_after_seq(0, MAX_LIST_LIMIT)
                .test_unwrap()
                .len(),
            1
        );

        let budgets = SqliteBudgetStore::open(&target_budget_db)
            .test_unwrap()
            .list_usages_after(MAX_LIST_LIMIT, None)
            .test_unwrap();
        assert_eq!(budgets.len(), 1);
        assert_eq!(budgets[0].invocation_count, 1);
        assert_eq!(budgets[0].total_cost_exposed, 5);
        assert_eq!(budgets[0].total_cost_realized_spend, 0);
        let mutation_events = SqliteBudgetStore::open(&target_budget_db)
            .test_unwrap()
            .list_mutation_events(10, Some("cap-1"), Some(0))
            .test_unwrap();
        assert_eq!(
            mutation_events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["hold-1:authorize", "hold-1:release"]
        );

        assert_eq!(peer_tool_seq(&target_state, "http://node-a"), 1);
        assert_eq!(peer_child_seq(&target_state, "http://node-a"), 1);
        assert_eq!(peer_lineage_seq(&target_state, "http://node-a"), 1);
        assert_eq!(
            peer_budget_cursor(&target_state, "http://node-a")
                .test_unwrap()
                .seq,
            2
        );
        assert_eq!(
            peer_revocation_cursor(&target_state, "http://node-a")
                .test_unwrap()
                .capability_id,
            "cap-1"
        );
        assert_eq!(
            with_peer_state(&target_state, "http://node-a", |peer| peer
                .snapshot_applied_count),
            Some(1)
        );
        assert_eq!(
            with_peer_state(&target_state, "http://node-a", |peer| peer.last_snapshot_at),
            Some(Some(generated_at))
        );
        assert!(!peer_should_force_snapshot(&target_state, "http://node-a"));
    }

    #[test]
    fn cluster_snapshot_round_trip_preserves_denied_budget_events_without_usage_rows() {
        let source_budget_db = unique_temp_path("cluster-source-denied-budgets", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-denied-budgets", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            None,
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            None,
            Some(target_budget_db.clone()),
        );

        {
            let budget_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            let allowed = budget_store
                .try_charge_cost_with_ids(
                    "cap-denied-only",
                    0,
                    Some(1),
                    25,
                    Some(50),
                    Some(10),
                    Some("cap-denied-only-hold-1"),
                    Some("cap-denied-only-hold-1:authorize"),
                )
                .test_unwrap();
            assert!(!allowed);
            assert!(budget_store
                .list_usages_after(MAX_LIST_LIMIT, None)
                .test_unwrap()
                .is_empty());
            let delta =
                collect_budget_mutation_event_views_after_seq(&budget_store, 0, MAX_LIST_LIMIT)
                    .test_unwrap();
            assert_eq!(delta.len(), 1);
            assert_eq!(delta[0].event_seq, 1);
            assert_eq!(delta[0].allowed, Some(false));
            assert_eq!(delta[0].usage_seq, None);
            assert!(collect_budget_mutation_event_views_after_seq(
                &budget_store,
                1,
                MAX_LIST_LIMIT
            )
            .test_unwrap()
            .is_empty());
        }

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.replication.budget_seq, 1);
        assert!(snapshot.budgets.is_empty());
        assert_eq!(snapshot.budget_mutation_events.len(), 1);
        assert_eq!(
            snapshot.budget_mutation_events[0].event_id,
            "cap-denied-only-hold-1:authorize"
        );
        assert_eq!(snapshot.budget_mutation_events[0].event_seq, 1);
        assert_eq!(snapshot.budget_mutation_events[0].allowed, Some(false));
        assert_eq!(snapshot.budget_mutation_events[0].usage_seq, None);

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
        assert!(target_store
            .list_usages_after(MAX_LIST_LIMIT, None)
            .test_unwrap()
            .is_empty());
        let mutation_events = target_store
            .list_mutation_events(10, Some("cap-denied-only"), Some(0))
            .test_unwrap();
        assert_eq!(mutation_events.len(), 1);
        assert_eq!(
            mutation_events[0].event_id,
            "cap-denied-only-hold-1:authorize"
        );
        assert_eq!(mutation_events[0].event_seq, 1);
        assert_eq!(mutation_events[0].allowed, Some(false));
        assert_eq!(mutation_events[0].usage_seq, None);
        drop(target_store);

        assert_eq!(
            peer_budget_cursor(&target_state, "http://node-a")
                .test_unwrap()
                .seq,
            1
        );
    }

    #[test]
    fn cluster_snapshot_round_trip_preserves_budget_usage_rows_without_mutation_events() {
        let source_budget_db = unique_temp_path("cluster-source-budget-usage-only", "sqlite3");
        let target_budget_db = unique_temp_path("cluster-target-budget-usage-only", "sqlite3");

        let source_state = state_with_cluster(
            "http://node-a",
            &["http://node-b"],
            None,
            None,
            Some(source_budget_db.clone()),
        );
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            None,
            None,
            Some(target_budget_db.clone()),
        );

        {
            let budget_store = SqliteBudgetStore::open(&source_budget_db).test_unwrap();
            budget_store
                .upsert_usage(&chio_kernel::BudgetUsageRecord {
                    capability_id: "cap-usage-only".to_string(),
                    grant_index: 0,
                    invocation_count: 7,
                    updated_at: 1_717_171_717,
                    seq: 42,
                    total_cost_exposed: 550,
                    total_cost_realized_spend: 375,
                })
                .test_unwrap();
            assert!(budget_store
                .list_mutation_events(10, Some("cap-usage-only"), Some(0))
                .test_unwrap()
                .is_empty());
        }

        update_peer_budget_cursor(
            &target_state,
            "http://node-a",
            BudgetCursor {
                seq: 99,
                updated_at: 1_717_171_718,
                capability_id: "stale-capability".to_string(),
                grant_index: 7,
            },
        );

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.replication.budget_seq, 0);
        assert_eq!(snapshot.budgets.len(), 1);
        assert!(snapshot.budget_mutation_events.is_empty());
        assert_eq!(snapshot.budgets[0].capability_id, "cap-usage-only");
        assert_eq!(snapshot.budgets[0].seq, Some(42));

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let target_store = SqliteBudgetStore::open(&target_budget_db).test_unwrap();
        let usages = target_store
            .list_usages_after(MAX_LIST_LIMIT, None)
            .test_unwrap();
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].capability_id, "cap-usage-only");
        assert_eq!(usages[0].invocation_count, 7);
        assert_eq!(usages[0].seq, 42);
        assert_eq!(usages[0].total_cost_exposed, 550);
        assert_eq!(usages[0].total_cost_realized_spend, 375);
        assert!(target_store
            .list_mutation_events(10, Some("cap-usage-only"), Some(0))
            .test_unwrap()
            .is_empty());
        drop(target_store);

        assert!(
            peer_budget_cursor(&target_state, "http://node-a").is_none(),
            "usage-only snapshots should clear any stale mutation cursor"
        );
    }

    #[test]
    fn budget_cursor_from_event_uses_mutation_event_sequence() {
        let cursor = budget_cursor_from_event(&BudgetMutationEventView {
            event_id: "evt-1".to_string(),
            hold_id: Some("hold-1".to_string()),
            capability_id: "cap-1".to_string(),
            grant_index: 2,
            kind: "authorize_exposure".to_string(),
            allowed: Some(true),
            recorded_at: 1_717_171_717,
            event_seq: 4,
            usage_seq: Some(9),
            exposure_units: 10,
            realized_spend_units: 0,
            max_invocations: Some(5),
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(50),
            invocation_count_after: 1,
            total_cost_exposed_after: 10,
            total_cost_realized_spend_after: 0,
            authority: None,
        });

        assert_eq!(cursor.seq, 4);
        assert_eq!(cursor.capability_id, "cap-1");
        assert_eq!(cursor.grant_index, 2);
    }

    #[test]
    fn budget_delta_import_handles_records_without_mutation_events() {
        let budget_db = unique_temp_path("cluster-records-only-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        let response = BudgetDeltaResponse {
            records: vec![BudgetUsageView {
                capability_id: "cap-records-only".to_string(),
                grant_index: 0,
                invocation_count: 3,
                total_cost_exposed: 55,
                total_cost_realized_spend: 21,
                updated_at: 1_717_171_717,
                seq: Some(42),
            }],
            mutation_events: Vec::new(),
        };

        let outcome = import_budget_delta_response(&mut store, &response, None).test_unwrap();
        assert_eq!(outcome.applied_count, 1);
        assert!(outcome.should_continue);
        assert_eq!(outcome.next_cursor.test_unwrap().seq, 42);

        let usage = store
            .get_usage("cap-records-only", 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(usage.invocation_count, 3);
        assert_eq!(usage.seq, 42);
        assert_eq!(usage.total_cost_exposed, 55);
        assert_eq!(usage.total_cost_realized_spend, 21);
        assert!(store
            .list_mutation_events(10, Some("cap-records-only"), Some(0))
            .test_unwrap()
            .is_empty());
    }

    #[test]
    fn budget_delta_import_rejects_oversized_peer_payloads() {
        let budget_db = unique_temp_path("cluster-oversized-budget-delta", "sqlite3");
        let mut store = SqliteBudgetStore::open(&budget_db).test_unwrap();
        let response = BudgetDeltaResponse {
            records: (0..=BUDGET_DELTA_MAX_RECORDS)
                .map(|idx| BudgetUsageView {
                    capability_id: format!("cap-{idx}"),
                    grant_index: 0,
                    invocation_count: 1,
                    total_cost_exposed: 0,
                    total_cost_realized_spend: 0,
                    updated_at: 1_717_171_717,
                    seq: Some(idx as u64 + 1),
                })
                .collect(),
            mutation_events: Vec::new(),
        };

        let result = import_budget_delta_response(&mut store, &response, None);
        let Err(error) = result else {
            panic!("oversized peer budget deltas should fail closed");
        };
        assert!(error.to_string().contains("budget delta response contains"));
    }

    #[test]
    fn apply_cluster_snapshot_seeds_authority_term_for_late_joiner_budget_writes() {
        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let target_state = state_with_cluster(
            "http://node-0",
            &["http://node-a", "http://node-b"],
            None,
            None,
            None,
        );

        for state in [&source_state, &target_state] {
            let cluster = state.cluster.as_ref().test_unwrap();
            let mut guard = cluster.lock().test_unwrap();
            for peer in guard.peers.values_mut() {
                peer.health = PeerHealth::Healthy;
                peer.last_contact_at = Some(unix_timestamp_now());
            }
        }

        let initial_target_consensus = cluster_consensus_view(&target_state).test_unwrap();
        assert_eq!(
            initial_target_consensus.leader_url.as_deref(),
            Some("http://node-0")
        );
        assert_eq!(initial_target_consensus.election_term, 1);

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        assert_eq!(snapshot.election_term, 1);
        assert_eq!(
            snapshot.authority_lease.as_ref().test_unwrap().leader_url,
            "http://node-a"
        );

        apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap();

        let seeded_consensus = cluster_consensus_view(&target_state).test_unwrap();
        assert_eq!(
            seeded_consensus.leader_url.as_deref(),
            Some("http://node-0")
        );
        assert_eq!(seeded_consensus.election_term, 2);
        let seeded_lease = cluster_authority_lease_view(&target_state).test_unwrap();
        assert_eq!(seeded_lease.authority_id, "http://node-0");
        assert_eq!(seeded_lease.lease_epoch, 2);
    }

    #[test]
    fn build_cluster_state_seeds_persisted_authority_fence_term() {
        let authority_db_path = unique_temp_path("cluster-authority-fence", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .test_unwrap();

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.election_term, 7);
        assert_eq!(guard.last_leader_url.as_deref(), Some("http://node-b"));

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn build_cluster_state_discards_persisted_authority_fence_for_unknown_leader() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-unknown-leader", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-z"), 7)
            .test_unwrap();

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.election_term, 7);
        assert!(
            guard.last_leader_url.is_none(),
            "unknown persisted leader should be cleared"
        );

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn build_cluster_state_discards_persisted_authority_fence_after_rotation() {
        let authority_db_path =
            unique_temp_path("cluster-authority-fence-stale-generation", "sqlite3");
        let authority = SqliteCapabilityAuthority::open(&authority_db_path).test_unwrap();
        authority
            .seed_cluster_fence(Some("http://node-b"), 7)
            .test_unwrap();
        authority.rotate().test_unwrap();

        let mut config = base_config();
        config.advertise_url = Some("http://node-a".to_string());
        config.peer_urls = vec!["http://node-b".to_string()];
        config.authority_db_path = Some(authority_db_path.clone());

        let cluster = build_cluster_state(&config, config.listen)
            .test_unwrap()
            .test_unwrap();
        let guard = cluster.lock().test_unwrap();
        assert_eq!(guard.election_term, 0);
        assert!(guard.last_leader_url.is_none());

        let _ = std::fs::remove_file(authority_db_path);
    }

    #[test]
    fn apply_cluster_snapshot_fails_when_authority_fence_persistence_fails() {
        let authority_db_path = unique_temp_path("cluster-authority-fence-dir", "d");
        std::fs::create_dir_all(&authority_db_path).test_unwrap();

        let source_state =
            state_with_cluster("http://node-a", &["http://node-b"], None, None, None);
        let target_state = state_with_cluster(
            "http://node-b",
            &["http://node-a"],
            Some(authority_db_path.clone()),
            None,
            None,
        );

        for state in [&source_state, &target_state] {
            let cluster = state.cluster.as_ref().test_unwrap();
            let mut guard = cluster.lock().test_unwrap();
            for peer in guard.peers.values_mut() {
                peer.health = PeerHealth::Healthy;
                peer.last_contact_at = Some(unix_timestamp_now());
            }
        }

        let snapshot = build_cluster_state_snapshot(&source_state).test_unwrap();
        let error =
            apply_cluster_snapshot(&target_state, "http://node-a", snapshot).test_unwrap_err();
        let error_text = error.to_string();
        assert!(
            error_text.contains("directory") || error_text.contains("open database file"),
            "unexpected error: {error_text}"
        );

        let _ = std::fs::remove_dir_all(authority_db_path);
    }
}
