#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::session::{SessionAuthMethod, SessionTransport};
    use p256::ecdsa::signature::Signer as _;
    use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
    use rsa::pss::BlindedSigningKey as RsaPssSigningKey;
    use rsa::rand_core::OsRng;
    use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    fn sign_jwt_with_header(
        header: Value,
        claims: &serde_json::Value,
        sign: impl Fn(&[u8]) -> Vec<u8>,
    ) -> String {
        let header =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize JWT header"));
        let payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize JWT claims"));
        let signing_input = format!("{header}.{payload}");
        let signature = URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes()));
        format!("{signing_input}.{signature}")
    }

    #[test]
    fn mcp_rate_limiter_caps_session_window() {
        let limiter = McpRateLimiter::new();
        for _ in 0..MCP_RATE_LIMIT_MAX_REQUESTS {
            assert!(limiter.check("session:test".to_string(), 120).is_ok());
        }

        let retry_after = limiter
            .check("session:test".to_string(), 120)
            .expect_err("session should be rate limited after the window budget is exhausted");
        assert_eq!(retry_after, 60);
        assert!(limiter.check("session:test".to_string(), 180).is_ok());
    }

    #[test]
    fn mcp_rate_limiter_caps_tracked_keys() {
        let limiter = McpRateLimiter::new();
        for idx in 0..MCP_RATE_LIMIT_MAX_KEYS {
            assert!(limiter.check(format!("session:{idx}"), 120).is_ok());
        }

        let retry_after = limiter
            .check("session:overflow".to_string(), 120)
            .expect_err("new rate-limit keys should be capped within a window");
        assert_eq!(retry_after, 60);
        assert!(limiter.check("session:0".to_string(), 120).is_ok());
    }

    #[test]
    fn mcp_rate_limit_key_ignores_unverified_client_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            MCP_SESSION_ID_HEADER,
            HeaderValue::from_static("session-secret"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer token-secret"),
        );

        let key = mcp_rate_limit_key("127.0.0.1:8080".parse().unwrap());
        assert_eq!(key, "ip:127.0.0.1");
        assert!(!key.contains("session-secret"));
        assert!(!key.contains("token-secret"));
    }

    fn sign_jwt_rs256(
        private_key: &rsa::RsaPrivateKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key.clone());
        sign_jwt_with_header(
            json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| signing_key.sign(message).to_vec(),
        )
    }

    fn sign_jwt_es256(
        signing_key: &p256::ecdsa::SigningKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        sign_jwt_with_header(
            json!({
                "alg": "ES256",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| {
                let signature: p256::ecdsa::Signature = signing_key.sign(message);
                signature.to_bytes().to_vec()
            },
        )
    }

    fn sign_jwt_ps256(
        private_key: &rsa::RsaPrivateKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        let signing_key = RsaPssSigningKey::<Sha256>::new(private_key.clone());
        sign_jwt_with_header(
            json!({
                "alg": "PS256",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| signing_key.sign_with_rng(&mut OsRng, message).to_vec(),
        )
    }

    fn sign_jwt_es384(
        signing_key: &p384::ecdsa::SigningKey,
        claims: &serde_json::Value,
        kid: &str,
    ) -> String {
        sign_jwt_with_header(
            json!({
                "alg": "ES384",
                "typ": "JWT",
                "kid": kid,
            }),
            claims,
            |message| {
                let signature: p384::ecdsa::Signature = signing_key.sign(message);
                signature.to_bytes().to_vec()
            },
        )
    }

    fn test_introspection_verifier(
        issuer: Option<&str>,
        audience: Option<&str>,
        required_scopes: &[&str],
    ) -> IntrospectionBearerVerifier {
        let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
        IntrospectionBearerVerifier {
            client: HttpClient::builder().build().expect("build http client"),
            introspection_url: Url::parse("http://127.0.0.1:9/introspect")
                .expect("parse introspection url"),
            client_id: None,
            client_secret: None,
            issuer: issuer.map(ToOwned::to_owned),
            audience: audience.map(ToOwned::to_owned),
            required_scopes: required_scopes
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
            sender_dpop_nonce_store,
            sender_dpop_config,
        }
    }

    fn test_sender_dpop_runtime() -> (Arc<DpopNonceStore>, DpopConfig) {
        let config = DpopConfig::default();
        let store = Arc::new(DpopNonceStore::new(
            config.nonce_store_capacity,
            Duration::from_secs(config.proof_ttl_secs),
        ));
        (store, config)
    }

    fn test_kernel_config() -> chio_kernel::KernelConfig {
        chio_kernel::KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
        }
    }

    fn empty_header_map() -> HeaderMap {
        HeaderMap::new()
    }

    fn test_remote_config() -> RemoteServeHttpConfig {
        RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().expect("parse listen addr"),
            auth_token: Some("remote-auth-token".to_string()),
            auth_jwt_public_key: None,
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: None,
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: None,
            auth_jwt_audience: None,
            admin_token: Some("admin-token".to_string()),
            control_url: None,
            control_token: None,
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec!["mcp:invoke".to_string()],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            manifest_public_key: None,
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
        }
    }

    fn sample_resume_record() -> RemoteSessionResumeRecord {
        RemoteSessionResumeRecord {
            session_id: "session-valid".to_string(),
            agent_id: "agent-valid".to_string(),
            auth_context: SessionAuthContext::streamable_http_oauth_bearer(
                Some("principal-valid".to_string()),
                Some("https://issuer.example".to_string()),
                Some("subject-valid".to_string()),
                Some("audience-valid".to_string()),
                vec!["mcp:invoke".to_string(), "mcp:read".to_string()],
                Some("token-fingerprint".to_string()),
                None,
            ),
            auth_mode_fingerprint: Some("auth-contract-v1".to_string()),
            policy_fingerprint: Some("policy-contract-v1".to_string()),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle: RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Ready,
                created_at: 10,
                last_seen_at: 11,
                idle_expires_at: 12,
                drain_deadline_at: None,
            },
            protocol_version: Some("2025-06-18".to_string()),
            peer_capabilities: PeerCapabilities::default(),
            initialize_params: json!({}),
            issued_capabilities: Vec::new(),
            resume_integrity_tag: None,
        }
    }

    #[test]
    fn shared_hosted_owner_notification_fanout_replays_to_all_live_taps() {
        let subscriber_a = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let subscriber_b = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let stats = SharedUpstreamNotificationStats::default();
        let subscribers: NotificationSubscriberList = Arc::new(StdMutex::new(vec![
            Arc::downgrade(&subscriber_a),
            Arc::downgrade(&subscriber_b),
        ]));

        fan_out_shared_upstream_notifications(
            &subscribers,
            &stats,
            vec![json!({
                "jsonrpc": "2.0",
                "method": "notifications/resources/list_changed"
            })],
        );

        let subscriber_a = subscriber_a.lock().expect("lock subscriber a");
        let subscriber_b = subscriber_b.lock().expect("lock subscriber b");
        assert_eq!(subscriber_a.len(), 1);
        assert_eq!(subscriber_b.len(), 1);
        assert_eq!(
            subscriber_a[0]["method"].as_str(),
            Some("notifications/resources/list_changed")
        );
        assert_eq!(subscriber_a.as_slices(), subscriber_b.as_slices());
        assert_eq!(stats.fanout_batches.load(Ordering::Relaxed), 1);
        assert_eq!(stats.fanout_notifications.load(Ordering::Relaxed), 1);
        assert_eq!(stats.fanout_targets.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn shared_hosted_owner_notification_fanout_tracks_pruned_dead_subscribers() {
        let stats = SharedUpstreamNotificationStats::default();
        let live = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let dropped = Arc::new(StdMutex::new(VecDeque::<Value>::new()));
        let subscribers: NotificationSubscriberList = Arc::new(StdMutex::new(vec![
            Arc::downgrade(&live),
            Arc::downgrade(&dropped),
        ]));
        drop(dropped);

        fan_out_shared_upstream_notifications(
            &subscribers,
            &stats,
            vec![json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            })],
        );

        assert_eq!(stats.pruned_subscribers.load(Ordering::Relaxed), 1);
        assert_eq!(stats.fanout_targets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn validate_resume_record_integrity_rejects_tampered_auth_context() {
        let config = test_remote_config();
        let seed = derive_resume_record_integrity_seed(&config)
            .expect("derive integrity seed")
            .expect("integrity seed");
        let mut record = sample_resume_record();
        record.resume_integrity_tag = Some(
            compute_resume_record_integrity_tag(&seed, &record)
                .expect("compute integrity tag"),
        );
        if let SessionAuthMethod::OAuthBearer { scopes, .. } = &mut record.auth_context.method {
            scopes.push("mcp:admin".to_string());
        } else {
            panic!("expected OAuth bearer auth context");
        }

        let error = validate_resume_record_integrity(&config, &record)
            .expect_err("tampered auth context should fail integrity validation");
        assert!(error
            .to_string()
            .contains("failed resumable integrity validation"));
    }

    #[test]
    fn stored_capability_issuer_revalidation_rejects_untrusted_restart_issuer() {
        let old_authority = Keypair::generate();
        let subject = Keypair::generate().public_key();
        let stale_capability = CapabilityToken::sign(
            chio_core::capability::CapabilityTokenBody {
                id: "cap-stale-issuer".to_string(),
                issuer: old_authority.public_key(),
                subject,
                scope: chio_core::capability::ChioScope::default(),
                issued_at: 1,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &old_authority,
        )
        .expect("sign stale capability");

        let restarted_kernel = chio_kernel::ChioKernel::new(test_kernel_config());
        assert!(!stored_capability_issuers_are_trusted(
            &restarted_kernel,
            std::slice::from_ref(&stale_capability)
        ));

        let mut trusted_kernel = chio_kernel::ChioKernel::new(test_kernel_config());
        trusted_kernel.set_capability_authority(Box::new(
            chio_kernel::LocalCapabilityAuthority::new(old_authority),
        ));
        assert!(stored_capability_issuers_are_trusted(
            &trusted_kernel,
            &[stale_capability]
        ));
    }

    #[test]
    fn validate_restored_peer_capabilities_rejects_tampered_record() {
        let mut record = sample_resume_record();
        record.initialize_params = json!({
            "capabilities": {
                "tools": { "listChanged": true },
                "resources": { "subscribe": true, "listChanged": true },
                "prompts": { "listChanged": true }
            }
        });
        record.peer_capabilities = PeerCapabilities::default();

        let error = validate_restored_peer_capabilities(&record)
            .expect_err("tampered peer capabilities should fail restore validation");
        assert!(error
            .to_string()
            .contains("failed peer capability re-validation"));
    }

    #[test]
    fn expected_resume_agent_id_is_revalidated_from_identity_federation_seed() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let seed_path = std::env::temp_dir().join(format!(
            "chio-identity-federation-resume-{}-{nonce}.seed",
            std::process::id()
        ));
        let mut config = test_remote_config();
        config.identity_federation_seed_path = Some(seed_path.clone());
        let auth_context = SessionAuthContext::streamable_http_oauth_bearer(
            Some("oidc:https://issuer.example#sub:user-123".to_string()),
            Some("https://issuer.example".to_string()),
            Some("user-123".to_string()),
            Some("audience-valid".to_string()),
            vec!["mcp:invoke".to_string()],
            Some("token-fingerprint".to_string()),
            None,
        );

        let expected = expected_resume_agent_id(&config, &auth_context)
            .expect("derive expected agent id")
            .expect("expected agent id");
        let foreign = derive_federated_agent_keypair(
            &seed_path,
            "oidc:https://issuer.example#sub:user-456",
        )
        .expect("derive foreign principal keypair")
        .public_key()
        .to_hex();

        assert_ne!(expected, foreign);

        let _ = std::fs::remove_file(seed_path);
    }

    #[test]
    fn load_active_session_records_skips_malformed_rows() {
        let path = std::env::temp_dir().join(format!(
            "chio-remote-active-{}-{}.sqlite3",
            std::process::id(),
            session_now_millis()
        ));
        let valid_record = RemoteSessionResumeRecord {
            session_id: "session-valid".to_string(),
            agent_id: "agent-valid".to_string(),
            auth_context: SessionAuthContext::streamable_http_static_bearer(
                "agent-valid",
                "token-fingerprint",
                None,
            ),
            auth_mode_fingerprint: Some("auth-contract-v1".to_string()),
            policy_fingerprint: Some("policy-contract-v1".to_string()),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle: RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Ready,
                created_at: 10,
                last_seen_at: 11,
                idle_expires_at: 12,
                drain_deadline_at: None,
            },
            protocol_version: Some("2025-06-18".to_string()),
            peer_capabilities: PeerCapabilities::default(),
            initialize_params: json!({}),
            issued_capabilities: Vec::new(),
            resume_integrity_tag: None,
        };
        persist_active_session_record(&path, &valid_record).expect("persist valid session row");

        let conn = open_session_state_db(&path).expect("open session state db");
        conn.execute(
            &format!(
                "INSERT OR REPLACE INTO {table} (session_id, updated_at, record_json)
                 VALUES (?1, ?2, ?3)",
                table = SESSION_ACTIVE_TABLE,
            ),
            params!["session-bad", session_now_millis() as i64, "{not json"],
        )
        .expect("insert malformed session row");
        drop(conn);

        let loaded = load_active_session_records(&path).expect("load active session records");
        assert_eq!(loaded.records.len(), 1);
        assert_eq!(loaded.records[0].session_id, "session-valid");
        assert_eq!(loaded.invalid_session_ids, vec!["session-bad".to_string()]);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_active_session_records_skips_terminal_tombstoned_rows() {
        let path = std::env::temp_dir().join(format!(
            "chio-remote-tombstoned-active-{}-{}.sqlite3",
            std::process::id(),
            session_now_millis()
        ));
        let auth_context = SessionAuthContext::streamable_http_static_bearer(
            "agent-terminal",
            "token-fingerprint",
            None,
        );
        let lifecycle = RemoteSessionLifecycleSnapshot {
            state: RemoteSessionState::Ready,
            created_at: 10,
            last_seen_at: 11,
            idle_expires_at: 12,
            drain_deadline_at: None,
        };
        let active_record = RemoteSessionResumeRecord {
            session_id: "session-terminal".to_string(),
            agent_id: "agent-terminal".to_string(),
            auth_context: auth_context.clone(),
            auth_mode_fingerprint: Some("auth-contract-v1".to_string()),
            policy_fingerprint: Some("policy-contract-v1".to_string()),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle: lifecycle.clone(),
            protocol_version: Some("2025-06-18".to_string()),
            peer_capabilities: PeerCapabilities::default(),
            initialize_params: json!({}),
            issued_capabilities: Vec::new(),
            resume_integrity_tag: None,
        };
        persist_active_session_record(&path, &active_record).expect("persist active session row");

        let terminal_record = RemoteSessionDiagnosticRecord {
            session_id: "session-terminal".to_string(),
            auth_context,
            capabilities: Vec::new(),
            lifecycle: RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Deleted,
                ..lifecycle
            },
            protocol_version: Some("2025-06-18".to_string()),
            ownership: RemoteSessionOwnershipSnapshot::default(),
            terminal_at: 13,
        };
        persist_terminal_session_record(&path, &terminal_record)
            .expect("persist terminal session tombstone");

        let loaded = load_active_session_records(&path).expect("load active session records");
        assert!(loaded.records.is_empty());
        assert_eq!(
            loaded.invalid_session_ids,
            vec!["session-terminal".to_string()]
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn purge_terminal_session_records_keeps_tombstones_for_stale_active_rows() {
        let path = std::env::temp_dir().join(format!(
            "chio-remote-terminal-retain-active-{}-{}.sqlite3",
            std::process::id(),
            session_now_millis()
        ));
        let auth_context = SessionAuthContext::streamable_http_static_bearer(
            "agent-terminal",
            "token-fingerprint",
            None,
        );
        let lifecycle = RemoteSessionLifecycleSnapshot {
            state: RemoteSessionState::Ready,
            created_at: 10,
            last_seen_at: 11,
            idle_expires_at: 12,
            drain_deadline_at: None,
        };
        let active_record = RemoteSessionResumeRecord {
            session_id: "session-terminal".to_string(),
            agent_id: "agent-terminal".to_string(),
            auth_context: auth_context.clone(),
            auth_mode_fingerprint: Some("auth-contract-v1".to_string()),
            policy_fingerprint: Some("policy-contract-v1".to_string()),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle: lifecycle.clone(),
            protocol_version: Some("2025-06-18".to_string()),
            peer_capabilities: PeerCapabilities::default(),
            initialize_params: json!({}),
            issued_capabilities: Vec::new(),
            resume_integrity_tag: None,
        };
        persist_active_session_record(&path, &active_record).expect("persist active session row");

        let terminal_record = RemoteSessionDiagnosticRecord {
            session_id: "session-terminal".to_string(),
            auth_context,
            capabilities: Vec::new(),
            lifecycle: RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Deleted,
                ..lifecycle
            },
            protocol_version: Some("2025-06-18".to_string()),
            ownership: RemoteSessionOwnershipSnapshot::default(),
            terminal_at: 10,
        };
        persist_terminal_session_record(&path, &terminal_record)
            .expect("persist terminal session tombstone");

        purge_terminal_session_records_before(&path, 11)
            .expect("purge should keep tombstone while active row remains");
        let records =
            load_terminal_session_records(&path).expect("load terminal session records after purge");
        assert!(records.contains_key("session-terminal"));

        delete_active_session_record(&path, "session-terminal").expect("delete active session row");
        purge_terminal_session_records_before(&path, 11)
            .expect("purge should remove tombstone after active row is gone");
        let records = load_terminal_session_records(&path)
            .expect("load terminal session records after second purge");
        assert!(!records.contains_key("session-terminal"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn remote_session_new_preserves_ready_lifecycle_on_restore() {
        let (input_tx, _input_rx) = mpsc::channel::<Value>();
        let (event_tx, _) = broadcast::channel::<RemoteSessionEvent>(8);
        let retained_notification_events =
            Arc::new(StdMutex::new(VecDeque::<RetainedRemoteSessionEvent>::new()));
        let next_event_id = Arc::new(AtomicU64::new(0));
        let lifecycle_policy = SessionLifecyclePolicy {
            idle_expiry_millis: 5_000,
            drain_grace_millis: 1_000,
            reaper_interval_millis: 100,
            tombstone_retention_millis: 10_000,
        };
        let session = RemoteSession::new(RemoteSessionInit {
            session_id: "session-restore".to_string(),
            agent_id: "agent-restore".to_string(),
            capabilities: Vec::new(),
            issued_capabilities: Vec::new(),
            auth_context: SessionAuthContext::streamable_http_static_bearer(
                "agent-restore",
                "restore-token",
                None,
            ),
            auth_mode_fingerprint: "auth-contract-v1".to_string(),
            policy_fingerprint: "policy-contract-v1".to_string(),
            hosted_isolation: RemoteHostedIsolationMode::DedicatedPerSession,
            lifecycle_policy: lifecycle_policy.clone(),
            protocol_version: None,
            peer_capabilities: None,
            initialize_params: None,
            lifecycle_snapshot: Some(RemoteSessionLifecycleSnapshot {
                state: RemoteSessionState::Ready,
                created_at: 11,
                last_seen_at: 12,
                idle_expires_at: 13,
                drain_deadline_at: Some(14),
            }),
            input_tx,
            event_tx,
            retained_notification_events,
            next_event_id,
            session_db_path: None,
            resume_integrity_secret: None,
        });

        let lifecycle = session.lifecycle_snapshot();
        assert_eq!(lifecycle.state, RemoteSessionState::Ready);
        assert_eq!(lifecycle.created_at, 11);
        assert_eq!(lifecycle.last_seen_at, 12);
        assert_eq!(lifecycle.idle_expires_at, 13);
        assert_eq!(lifecycle.drain_deadline_at, None);
    }

    #[test]
    fn chio_oauth_discovery_profile_metadata_advertises_sender_constraints() {
        let metadata =
            build_chio_oauth_authorization_profile_metadata().expect("build Chio auth profile");
        let profile: ChioOAuthAuthorizationProfile =
            serde_json::from_value(metadata.clone()).expect("parse Chio auth profile");
        assert_eq!(profile.id, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID);
        assert_eq!(profile.schema, CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA);
        assert_eq!(
            profile.sender_constraints.subject_binding,
            CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT
        );
        assert!(profile
            .sender_constraints
            .proof_types_supported
            .iter()
            .any(|proof| proof == CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP));
        assert!(profile
            .sender_constraints
            .proof_types_supported
            .iter()
            .any(|proof| proof == chio_kernel::operator_report::CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS));
        assert!(profile
            .sender_constraints
            .proof_types_supported
            .iter()
            .any(|proof| proof
                == chio_kernel::operator_report::CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION));
        assert_eq!(
            profile
                .request_time_contract
                .authorization_details_parameter
                .as_str(),
            CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER
        );
        assert!(
            profile
                .resource_binding
                .request_resource_must_match_protected_resource
        );
        assert!(
            !profile
                .artifact_boundary
                .reviewer_evidence_runtime_admission_supported
        );
        assert_eq!(metadata["discoveryInformationalOnly"].as_bool(), Some(true));
    }

    #[test]
    fn chio_oauth_discovery_validation_rejects_profile_mismatch() {
        let protected_resource_metadata = ProtectedResourceMetadata {
            resource: "https://edge.example/mcp".to_string(),
            resource_metadata_url: "https://edge.example/.well-known/oauth-protected-resource/mcp"
                .to_string(),
            authorization_servers: vec!["https://edge.example/oauth".to_string()],
            scopes_supported: vec!["mcp:invoke".to_string()],
            chio_authorization_profile: build_chio_oauth_authorization_profile_metadata()
                .expect("build protected Chio auth profile"),
        };
        let authorization_server_metadata = AuthorizationServerMetadata {
            metadata_path: "/.well-known/oauth-authorization-server/oauth".to_string(),
            document: json!({
                "issuer": "https://edge.example/oauth",
                "chio_authorization_profile": {
                    "schema": CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA,
                    "id": "mismatched-profile",
                    "authoritativeSource": "governed_receipt_projection",
                    "authorizationDetailTypes": ["chio_governed_tool"],
                    "transactionContextFields": ["intentId", "intentHash"],
                    "senderConstraints": {
                        "schema": "chio.oauth.sender-constraint.v1",
                        "subjectBinding": CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT,
                        "proofTypesSupported": [CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP],
                        "proofRequiredWhen": "matchedGrant.dpopRequired == true",
                        "runtimeAssuranceBindingFields": ["runtimeAssuranceTier"],
                        "delegatedCallChainField": "callChain",
                        "unsupportedSenderShapesFailClosed": true
                    },
                    "unsupportedShapesFailClosed": true
                }
            }),
        };

        let error = validate_chio_oauth_discovery_metadata_pair(
            &protected_resource_metadata,
            &authorization_server_metadata,
        )
        .expect_err("mismatched discovery metadata should fail");
        assert!(
            error.to_string().contains("Chio authorization profile id"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn remote_session_auth_context_uses_static_bearer_fingerprint_and_origin() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, HeaderValue::from_static("http://localhost:3000"));

        let auth_context = build_static_bearer_session_auth_context(&headers, "test-token");
        assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
        assert_eq!(
            auth_context.origin.as_deref(),
            Some("http://localhost:3000")
        );
        assert!(auth_context.is_authenticated());

        match &auth_context.method {
            SessionAuthMethod::StaticBearer {
                principal,
                token_fingerprint,
            } => {
                assert_eq!(token_fingerprint, &sha256_hex(b"test-token"));
                assert!(principal.starts_with("static-bearer:"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_builds_oauth_session_auth_context() {
        let keypair = Keypair::generate();
        let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
        let token = sign_jwt(
            &keypair,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-123",
                "aud": "chio-mcp",
                "scope": "tools.read tools.write",
                "client_id": "client-abc",
                "tid": "tenant-123",
                "org_id": "org-789",
                "groups": ["ops", "eng"],
                "roles": ["reviewer", "operator"],
                "exp": unix_now() + 300,
            }),
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Static(keypair.public_key()),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("chio-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
            sender_dpop_nonce_store,
            sender_dpop_config,
        };

        let auth_context = verifier
            .authenticate_token(
                &token,
                &empty_header_map(),
                Some("http://localhost:3000".to_string()),
                None,
                "POST",
                "chio-mcp",
            )
            .unwrap();
        assert_eq!(auth_context.transport, SessionTransport::StreamableHttp);
        assert_eq!(
            auth_context.origin.as_deref(),
            Some("http://localhost:3000")
        );

        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal,
                issuer,
                subject,
                audience,
                scopes,
                federated_claims,
                enterprise_identity,
                token_fingerprint,
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-123")
                );
                assert_eq!(issuer.as_deref(), Some("https://issuer.example"));
                assert_eq!(subject.as_deref(), Some("user-123"));
                assert_eq!(audience.as_deref(), Some("chio-mcp"));
                assert_eq!(
                    scopes,
                    &vec!["tools.read".to_string(), "tools.write".to_string()]
                );
                assert_eq!(federated_claims.client_id.as_deref(), Some("client-abc"));
                assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
                assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
                assert_eq!(
                    federated_claims.groups,
                    vec!["eng".to_string(), "ops".to_string()]
                );
                assert_eq!(
                    federated_claims.roles,
                    vec!["operator".to_string(), "reviewer".to_string()]
                );
                assert_eq!(
                    token_fingerprint.as_deref(),
                    Some(sha256_hex(token.as_bytes()).as_str())
                );
                let enterprise_identity = enterprise_identity
                    .as_ref()
                    .expect("enterprise identity should be populated");
                assert_eq!(enterprise_identity.provider_id, "https://issuer.example");
                assert_eq!(enterprise_identity.provider_record_id, None);
                assert_eq!(enterprise_identity.provider_kind, "oidc_jwks");
                assert_eq!(
                    enterprise_identity.federation_method,
                    EnterpriseFederationMethod::Jwt
                );
                assert_eq!(
                    enterprise_identity.principal,
                    "oidc:https://issuer.example#sub:user-123"
                );
                assert_eq!(
                    enterprise_identity.subject_key,
                    derive_enterprise_subject_key(
                        "https://issuer.example",
                        "oidc:https://issuer.example#sub:user-123",
                    )
                );
                assert_eq!(enterprise_identity.tenant_id.as_deref(), Some("tenant-123"));
                assert_eq!(
                    enterprise_identity.organization_id.as_deref(),
                    Some("org-789")
                );
                assert_eq!(
                    enterprise_identity.attribute_sources.get("principal"),
                    Some(&"sub".to_string())
                );
                assert_eq!(
                    enterprise_identity.attribute_sources.get("groups"),
                    Some(&"groups".to_string())
                );
                assert_eq!(
                    enterprise_identity.attribute_sources.get("roles"),
                    Some(&"roles".to_string())
                );
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_rs256_jwks_token() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
        let token = sign_jwt_rs256(
            &private_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-rsa",
                "aud": "chio-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "rsa-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "rsa-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::Rsa(public_key),
                        alg_hint: Some("RS256".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("chio-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
            sender_dpop_nonce_store,
            sender_dpop_config,
        };

        let auth_context = verifier
            .authenticate_token(
                &token,
                &empty_header_map(),
                Some("http://localhost:3000".to_string()),
                None,
                "POST",
                "chio-mcp",
            )
            .unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-rsa")
                );
                assert_eq!(subject.as_deref(), Some("user-rsa"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_es256_jwks_token() {
        let signing_key =
            p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
        let token = sign_jwt_es256(
            &signing_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-ec",
                "aud": "chio-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "ec-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "ec-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::P256(*signing_key.verifying_key()),
                        alg_hint: Some("ES256".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("chio-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
            sender_dpop_nonce_store,
            sender_dpop_config,
        };

        let auth_context = verifier
            .authenticate_token(&token, &empty_header_map(), None, None, "POST", "chio-mcp")
            .unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-ec")
                );
                assert_eq!(subject.as_deref(), Some("user-ec"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_ps256_jwks_token() {
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
        let token = sign_jwt_ps256(
            &private_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-pss",
                "aud": "chio-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "pss-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "pss-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::Rsa(public_key),
                        alg_hint: Some("PS256".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("chio-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
            sender_dpop_nonce_store,
            sender_dpop_config,
        };

        let auth_context = verifier
            .authenticate_token(&token, &empty_header_map(), None, None, "POST", "chio-mcp")
            .unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-pss")
                );
                assert_eq!(subject.as_deref(), Some("user-pss"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn jwt_bearer_verifier_authenticates_es384_jwks_token() {
        let signing_key =
            p384::ecdsa::SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
        let (sender_dpop_nonce_store, sender_dpop_config) = test_sender_dpop_runtime();
        let token = sign_jwt_es384(
            &signing_key,
            &json!({
                "iss": "https://issuer.example",
                "sub": "user-es384",
                "aud": "chio-mcp",
                "scope": "tools.read",
                "exp": unix_now() + 300,
            }),
            "ec384-key-1",
        );
        let verifier = JwtBearerVerifier {
            key_source: JwtVerificationKeySource::Jwks(JwtJwksKeySet {
                keys_by_kid: HashMap::from([(
                    "ec384-key-1".to_string(),
                    JwtResolvedJwkPublicKey {
                        key: JwtResolvedPublicKey::P384(*signing_key.verifying_key()),
                        alg_hint: Some("ES384".to_string()),
                    },
                )]),
                anonymous_keys: vec![],
            }),
            issuer: Some("https://issuer.example".to_string()),
            audience: Some("chio-mcp".to_string()),
            required_scopes: vec![],
            provider_profile: JwtProviderProfile::Generic,
            enterprise_provider_registry: None,
            sender_dpop_nonce_store,
            sender_dpop_config,
        };

        let auth_context = verifier
            .authenticate_token(&token, &empty_header_map(), None, None, "POST", "chio-mcp")
            .unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal, subject, ..
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:user-es384")
                );
                assert_eq!(subject.as_deref(), Some("user-es384"));
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn introspection_bearer_verifier_accepts_active_token_with_resource_claim() {
        let verifier = test_introspection_verifier(
            Some("https://issuer.example"),
            Some("chio-mcp"),
            &["mcp:invoke"],
        );
        let auth_context = verifier
            .session_auth_context_from_introspection(super::IntrospectionSessionAuthInput {
                token: "opaque-token",
                headers: &empty_header_map(),
                introspection: OAuthIntrospectionResponse {
                    active: true,
                    token_type: Some("Bearer".to_string()),
                    claims: JwtClaims {
                        iss: Some("https://issuer.example".to_string()),
                        sub: Some("opaque-user".to_string()),
                        aud: None,
                        scope: Some("mcp:invoke tools.read".to_string()),
                        scp: vec![],
                        client_id: Some("client-123".to_string()),
                        jti: None,
                        oid: None,
                        azp: None,
                        appid: None,
                        tid: Some("tenant-123".to_string()),
                        tenant_id: None,
                        org_id: Some("org-789".to_string()),
                        organization_id: None,
                        groups: vec!["ops".to_string(), "eng".to_string()],
                        roles: vec!["operator".to_string()],
                        resource: Some("chio-mcp".to_string()),
                        authorization_details: None,
                        chio_transaction_context: None,
                        cnf: None,
                        exp: Some(unix_now() + 300),
                        nbf: None,
                    },
                },
                origin: Some("http://localhost:3000".to_string()),
                protected_resource_metadata: None,
                expected_method: "POST",
                expected_target: "chio-mcp",
            })
            .unwrap();
        match &auth_context.method {
            SessionAuthMethod::OAuthBearer {
                principal,
                issuer,
                subject,
                audience,
                scopes,
                federated_claims,
                enterprise_identity,
                token_fingerprint,
            } => {
                assert_eq!(
                    principal.as_deref(),
                    Some("oidc:https://issuer.example#sub:opaque-user")
                );
                assert_eq!(issuer.as_deref(), Some("https://issuer.example"));
                assert_eq!(subject.as_deref(), Some("opaque-user"));
                assert_eq!(audience.as_deref(), Some("chio-mcp"));
                assert_eq!(
                    scopes,
                    &vec!["mcp:invoke".to_string(), "tools.read".to_string()]
                );
                assert_eq!(federated_claims.client_id.as_deref(), Some("client-123"));
                assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
                assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
                assert_eq!(
                    federated_claims.groups,
                    vec!["eng".to_string(), "ops".to_string()]
                );
                assert_eq!(federated_claims.roles, vec!["operator".to_string()]);
                assert_eq!(
                    token_fingerprint.as_deref(),
                    Some(sha256_hex(b"opaque-token").as_str())
                );
                let enterprise_identity = enterprise_identity
                    .as_ref()
                    .expect("enterprise identity should be populated");
                assert_eq!(enterprise_identity.provider_kind, "oauth_introspection");
                assert_eq!(
                    enterprise_identity.federation_method,
                    EnterpriseFederationMethod::Introspection
                );
                assert_eq!(
                    enterprise_identity.subject_key,
                    derive_enterprise_subject_key(
                        "https://issuer.example",
                        "oidc:https://issuer.example#sub:opaque-user",
                    )
                );
            }
            other => panic!("unexpected auth method: {other:?}"),
        }
    }

    #[test]
    fn introspection_bearer_verifier_rejects_inactive_token() {
        let verifier = test_introspection_verifier(None, None, &[]);
        let error = verifier
            .session_auth_context_from_introspection(super::IntrospectionSessionAuthInput {
                token: "opaque-token",
                headers: &empty_header_map(),
                introspection: OAuthIntrospectionResponse {
                    active: false,
                    token_type: Some("Bearer".to_string()),
                    claims: JwtClaims {
                        iss: None,
                        sub: Some("opaque-user".to_string()),
                        aud: None,
                        scope: None,
                        scp: vec![],
                        client_id: None,
                        jti: None,
                        oid: None,
                        azp: None,
                        appid: None,
                        tid: None,
                        tenant_id: None,
                        org_id: None,
                        organization_id: None,
                        groups: Vec::new(),
                        roles: Vec::new(),
                        resource: None,
                        authorization_details: None,
                        chio_transaction_context: None,
                        cnf: None,
                        exp: None,
                        nbf: None,
                    },
                },
                origin: None,
                protected_resource_metadata: None,
                expected_method: "POST",
                expected_target: "chio-mcp",
            })
            .unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn build_federated_principal_prefers_subject_over_client_id() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://issuer.example/".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: Some("client-abc".to_string()),
                jti: None,
                oid: None,
                azp: None,
                appid: None,
                tid: None,
                tenant_id: None,
                org_id: None,
                organization_id: None,
                groups: Vec::new(),
                roles: Vec::new(),
                resource: None,
                authorization_details: None,
                chio_transaction_context: None,
                cnf: None,
                exp: None,
                nbf: None,
            },
            None,
            None,
            JwtProviderProfile::Generic,
        )
        .unwrap();
        assert_eq!(principal, "oidc:https://issuer.example#sub:user-123");
    }

    #[test]
    fn build_federated_principal_azure_ad_prefers_oid_and_appid() {
        let principal = build_federated_principal(
            &JwtClaims {
                iss: Some("https://login.microsoftonline.com/example/v2.0".to_string()),
                sub: Some("subject-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                jti: None,
                oid: Some("object-456".to_string()),
                azp: None,
                appid: Some("app-789".to_string()),
                tid: None,
                tenant_id: None,
                org_id: None,
                organization_id: None,
                groups: Vec::new(),
                roles: Vec::new(),
                resource: None,
                authorization_details: None,
                chio_transaction_context: None,
                cnf: None,
                exp: None,
                nbf: None,
            },
            None,
            None,
            JwtProviderProfile::AzureAd,
        )
        .unwrap();
        assert_eq!(
            principal,
            "oidc:https://login.microsoftonline.com/example/v2.0#oid:object-456"
        );
    }

    #[test]
    fn build_federated_claims_normalizes_enterprise_identity_metadata() {
        let federated_claims = build_federated_claims(
            &JwtClaims {
                iss: Some("https://issuer.example".to_string()),
                sub: Some("user-123".to_string()),
                aud: None,
                scope: None,
                scp: vec![],
                client_id: None,
                jti: None,
                oid: Some("object-456".to_string()),
                azp: Some("client-azp".to_string()),
                appid: Some("client-app".to_string()),
                tid: Some("tenant-123".to_string()),
                tenant_id: Some("tenant-fallback".to_string()),
                org_id: Some("org-789".to_string()),
                organization_id: Some("org-fallback".to_string()),
                groups: vec![
                    " ops ".to_string(),
                    "eng".to_string(),
                    "eng".to_string(),
                    "".to_string(),
                ],
                roles: vec![" reviewer ".to_string(), "operator".to_string()],
                resource: None,
                authorization_details: None,
                chio_transaction_context: None,
                cnf: None,
                exp: None,
                nbf: None,
            },
            JwtProviderProfile::AzureAd,
        );
        assert_eq!(federated_claims.client_id.as_deref(), Some("client-azp"));
        assert_eq!(federated_claims.object_id.as_deref(), Some("object-456"));
        assert_eq!(federated_claims.tenant_id.as_deref(), Some("tenant-123"));
        assert_eq!(federated_claims.organization_id.as_deref(), Some("org-789"));
        assert_eq!(
            federated_claims.groups,
            vec!["eng".to_string(), "ops".to_string()]
        );
        assert_eq!(
            federated_claims.roles,
            vec!["operator".to_string(), "reviewer".to_string()]
        );
    }

    #[test]
    fn provider_profile_can_derive_standard_oidc_discovery_url_from_issuer() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: Some(JwtProviderProfile::Okta),
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: Some("https://id.example.com/oauth2/default".to_string()),
            auth_jwt_audience: None,
            admin_token: Some("admin-token".to_string()),
            control_url: None,
            control_token: None,
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            manifest_public_key: None,
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
        };

        let discovery_url = resolve_identity_provider_discovery_url(&config)
            .unwrap()
            .expect("discovery url");
        assert_eq!(
            discovery_url.as_str(),
            "https://id.example.com/oauth2/default/.well-known/openid-configuration"
        );
    }

    #[test]
    fn identity_federation_derives_stable_keypair_per_principal() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seed_path = std::env::temp_dir().join(format!(
            "chio-identity-federation-seed-{}-{nonce}.seed",
            std::process::id()
        ));

        let first =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let second =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-123")
                .unwrap();
        let other =
            derive_federated_agent_keypair(&seed_path, "oidc:https://issuer.example#sub:user-456")
                .unwrap();

        assert_eq!(first.public_key().to_hex(), second.public_key().to_hex());
        assert_ne!(first.public_key().to_hex(), other.public_key().to_hex());
    }

    #[test]
    fn jwt_remote_auth_requires_separate_admin_token() {
        let config = RemoteServeHttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            auth_token: None,
            auth_jwt_public_key: Some(Keypair::generate().public_key().to_hex()),
            auth_jwt_discovery_url: None,
            auth_introspection_url: None,
            auth_introspection_client_id: None,
            auth_introspection_client_secret: None,
            auth_jwt_provider_profile: None,
            auth_server_seed_path: None,
            identity_federation_seed_path: None,
            enterprise_providers_file: None,
            auth_jwt_issuer: None,
            auth_jwt_audience: None,
            admin_token: None,
            control_url: None,
            control_token: None,
            public_base_url: None,
            auth_servers: vec![],
            auth_authorization_endpoint: None,
            auth_token_endpoint: None,
            auth_registration_endpoint: None,
            auth_jwks_uri: None,
            auth_scopes: vec![],
            auth_subject: "operator".to_string(),
            auth_code_ttl_secs: 300,
            auth_access_token_ttl_secs: 600,
            receipt_db_path: None,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: None,
            session_db_path: None,
            policy_path: PathBuf::from("policy.yaml"),
            server_id: "srv".to_string(),
            server_name: "srv".to_string(),
            server_version: "0.1.0".to_string(),
            manifest_public_key: None,
            page_size: 50,
            tools_list_changed: false,
            shared_hosted_owner: false,
            wrapped_command: "python3".to_string(),
            wrapped_args: vec!["mock.py".to_string()],
        };

        let error = build_remote_auth_state(&config, "127.0.0.1:0".parse().unwrap(), None, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("--admin-token"));
    }

    #[test]
    fn shared_upstream_notification_fanout_copies_notifications_and_prunes_dead_queues() {
        let subscribers = Arc::new(StdMutex::new(Vec::new()));
        let stats = SharedUpstreamNotificationStats::default();
        let queue_a = Arc::new(StdMutex::new(VecDeque::new()));
        let queue_b = Arc::new(StdMutex::new(VecDeque::new()));
        let dropped_queue = Arc::new(StdMutex::new(VecDeque::new()));
        if let Ok(mut guard) = subscribers.lock() {
            guard.push(Arc::downgrade(&queue_a));
            guard.push(Arc::downgrade(&queue_b));
            guard.push(Arc::downgrade(&dropped_queue));
        }
        drop(dropped_queue);

        fan_out_shared_upstream_notifications(
            &subscribers,
            &stats,
            vec![
                json!({"jsonrpc": "2.0", "method": "notifications/resources/list_changed"}),
                json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
            ],
        );

        let queue_a = queue_a.lock().unwrap();
        let queue_b = queue_b.lock().unwrap();
        assert_eq!(queue_a.len(), 2);
        assert_eq!(queue_b.len(), 2);
        assert_eq!(
            queue_a[0]["method"].as_str(),
            Some("notifications/resources/list_changed")
        );
        assert_eq!(
            queue_a[1]["method"].as_str(),
            Some("notifications/tools/list_changed")
        );
        assert_eq!(queue_a.as_slices(), queue_b.as_slices());
        drop(queue_a);
        drop(queue_b);

        let subscriber_count = subscribers.lock().unwrap().len();
        assert_eq!(subscriber_count, 2);
    }

    fn sign_jwt(keypair: &Keypair, claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "alg": "EdDSA",
                "typ": "JWT"
            }))
            .unwrap(),
        );
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let signature = keypair.sign(signing_input.as_bytes()).to_bytes();
        let signature = URL_SAFE_NO_PAD.encode(signature);
        format!("{signing_input}.{signature}")
    }
}
