use super::super::super::*;
use super::super::budget::build_remote_budget_store;
use super::handle_trust_control_metrics;
use chio_test_support::prelude::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn metrics_state(service_token: &str) -> TrustServiceState {
    let config = TrustServiceConfig {
        listen: "127.0.0.1:0".parse().test_unwrap(),
        service_token: service_token.to_string(),
        tenant_read_tokens: BTreeMap::new(),
        receipt_db_path: None,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        budget_db_path: None,
        joint_authority_db_path: None,
        fiscal_runtime: None,
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
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        #[cfg(feature = "cognition-market-experimental")]
        finding_market: None,
    };
    TrustServiceState {
        config,
        joint_authority_store: None,
        fiscal_runtime: None,
        budget_store: None,
        revocation_store: None,
        enterprise_provider_registry: None,
        verifier_policy_registry: None,
        federation_admission_rate_limiter: Arc::new(Mutex::new(
            FederationAdmissionRateLimiter::default(),
        )),
        cluster: None,
        cluster_progress: None,
        #[cfg(feature = "cognition-market-experimental")]
        finding_rail: None,
    }
}

/// The /metrics route shares the trust-control listener and must fail closed.
/// An unauthenticated scrape is rejected with 401 rather than exposing
/// operational counters and guard labels.
#[tokio::test]
async fn trust_control_metrics_rejects_unauthenticated_request() {
    let state = metrics_state("service-secret");
    let response = handle_trust_control_metrics(State(state), HeaderMap::new()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn fiscal_runtime_status_is_authenticated_and_disabled_by_default() {
    let state = metrics_state("service-secret");
    let unauthorized = handle_fiscal_runtime_status(State(state.clone()), HeaderMap::new()).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    let disabled = handle_fiscal_runtime_status(State(state), headers).await;
    assert_eq!(disabled.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn fiscal_marketplace_consumers_require_auth_and_a_runtime() {
    let state = metrics_state("service-secret");
    let price = FiscalMarketplacePriceRequest {
        base: chio_appraisal::MarketplaceBasePrice::new(1_000, "USD"),
        context: chio_appraisal::MarketplacePricingContext::new(
            "tenant-a",
            chio_appraisal::MarketplaceReputationTier::Tier1,
        ),
    };
    let unauthorized =
        handle_fiscal_marketplace_price(State(state.clone()), HeaderMap::new(), Json(price)).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    let disabled = handle_fiscal_marketplace_credit_limit(
        State(state),
        headers,
        Json(FiscalMarketplaceCreditLimitRequest {
            tenant_id: "tenant-a".to_owned(),
            currency: "USD".to_owned(),
        }),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::CONFLICT);
}

#[test]
fn fiscal_marketplace_credit_limit_rejects_client_trust_claims() {
    let request = serde_json::json!({
        "tenant_id": "tenant-a",
        "currency": "USD",
        "reputation_tier": "tier3",
        "publisher_revoked": false,
    });
    assert!(serde_json::from_value::<FiscalMarketplaceCreditLimitRequest>(request).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_legacy_holds_use_exact_versioned_rich_lifecycle(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let temp = crate::durable_admission::private_tempdir()?;
    let sqlite = Arc::new(SqliteBudgetStore::open(
        temp.path().join("legacy-budget.sqlite3"),
    )?);
    let mut state = metrics_state("service-secret");
    state.budget_store = Some(sqlite);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let server =
        tokio::spawn(async move { axum::serve(listener, super::build_router(state)).await });

    let lifecycle = tokio::task::spawn_blocking(move || {
        let store = build_remote_budget_store(&url, "service-secret")?;
        let authorize = |hold_id: &str| {
            store.authorize_budget_hold(BudgetAuthorizeHoldRequest {
                capability_id: "legacy-rich".to_string(),
                grant_index: 0,
                max_invocations: None,
                invocation_quotas: Vec::new(),
                cumulative_approval: None,
                admission_binding: None,
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(500),
                hold_id: Some(hold_id.to_string()),
                event_id: Some(format!("{hold_id}:authorize")),
                authority: None,
            })
        };

        let capture_hold = "legacy-capture";
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = authorize(capture_hold)? else {
            return Err(std::io::Error::other("legacy capture hold was not authorized").into());
        };
        assert!(authorized.admission_binding.is_none());
        let authorization_usage = store
            .get_usage("legacy-rich", 0)?
            .ok_or_else(|| std::io::Error::other("authorization usage was not cached"))?;
        std::thread::sleep(Duration::from_millis(1_100));
        let capture = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "legacy-rich".to_string(),
            grant_index: 0,
            hold_id: capture_hold.to_string(),
            event_id: format!("{capture_hold}:capture-invocation"),
            trusted_time: None,
            authority: None,
        })?;
        let capture = match capture {
            BudgetInvocationCaptureDecision::Captured(mutation) => mutation,
            BudgetInvocationCaptureDecision::AlreadyCaptured(_) => {
                return Err(std::io::Error::other("fresh capture replayed").into())
            }
        };
        assert!(capture.admission_binding.is_none());
        assert_eq!(capture.invocation_state, BudgetInvocationState::Captured);
        assert_eq!(
            capture.metadata.event_id.as_deref(),
            Some("legacy-capture:capture-invocation")
        );
        let capture_commit = capture
            .metadata
            .budget_commit_index
            .ok_or_else(|| std::io::Error::other("capture omitted commit"))?;
        let capture_usage = store
            .get_usage("legacy-rich", 0)?
            .ok_or_else(|| std::io::Error::other("capture usage was not cached"))?;
        assert_eq!(capture_usage.seq, authorization_usage.seq);
        assert_eq!(capture_usage.updated_at, authorization_usage.updated_at);
        assert!(capture_usage.seq < capture_commit);

        let release_hold = "legacy-release";
        assert!(matches!(
            authorize(release_hold)?,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let release = store.release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: "legacy-rich".to_string(),
            grant_index: 0,
            released_exposure_units: 25,
            hold_id: Some(release_hold.to_string()),
            event_id: Some(format!("{release_hold}:release")),
            authority: None,
        })?;
        assert!(release.admission_binding.is_none());
        assert_eq!(release.exposure_units, 25);

        let reverse_hold = "legacy-reverse";
        assert!(matches!(
            authorize(reverse_hold)?,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let reverse = store.reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: "legacy-rich".to_string(),
            grant_index: 0,
            reversed_exposure_units: 100,
            hold_id: Some(reverse_hold.to_string()),
            event_id: Some(format!("{reverse_hold}:reverse")),
            expected_cumulative_approval_state: None,
            authority: None,
        })?;
        assert!(reverse.admission_binding.is_none());
        assert_eq!(reverse.invocation_state, BudgetInvocationState::Reversed);

        let reconcile_hold = "legacy-reconcile";
        assert!(matches!(
            authorize(reconcile_hold)?,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "legacy-rich".to_string(),
            grant_index: 0,
            hold_id: reconcile_hold.to_string(),
            event_id: format!("{reconcile_hold}:capture-invocation"),
            trusted_time: None,
            authority: None,
        })?;
        let reconcile = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: "legacy-rich".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some(reconcile_hold.to_string()),
            event_id: Some(format!("{reconcile_hold}:reconcile")),
            authority: None,
        })?;
        assert!(reconcile.admission_binding.is_none());
        assert_eq!(reconcile.monetary_state, BudgetMonetaryState::Reconciled);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?;
    lifecycle?;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn versioned_rich_lifecycle_does_not_mutate_legacy_cluster_follower(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = crate::durable_admission::private_tempdir()?;
    let sqlite = Arc::new(SqliteBudgetStore::open(
        temp.path().join("cluster-budget.sqlite3"),
    )?);
    assert!(matches!(
        sqlite.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cluster-rich".to_string(),
            grant_index: 0,
            max_invocations: None,
            invocation_quotas: Vec::new(),
            cumulative_approval: None,
            admission_binding: None,
            requested_exposure_units: 10,
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(10),
            hold_id: Some("cluster-hold".to_string()),
            event_id: Some("cluster-hold:authorize".to_string()),
            authority: None,
        })?,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let mut state = metrics_state("service-secret");
    state.budget_store = Some(sqlite.clone());
    state.config.advertise_url = Some("http://127.0.0.1:3200".to_string());
    state.config.peer_urls = vec!["http://127.0.0.1:3300".to_string()];
    state.cluster =
        crate::trust_control::cluster::build_cluster_state(&state.config, state.config.listen)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    let response = super::handle_structured_budget_capture_invocation(
        State(state),
        headers,
        Json(StructuredBudgetCaptureInvocationRequest {
            schema: STRUCTURED_BUDGET_REQUEST_SCHEMA.to_string(),
            capability_id: "cluster-rich".to_string(),
            grant_index: 0,
            hold_id: "cluster-hold".to_string(),
            event_id: "cluster-hold:capture-invocation".to_string(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(sqlite
        .mutation_event_for_event_id("cluster-hold:capture-invocation")?
        .is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_structured_denial_has_no_invented_usage_sequence_or_cache_mutation(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let temp = tempfile::tempdir()?;
    crate::create_private_directory(temp.path())?;
    let database = temp.path().join("denied-authority.sqlite3");
    let lock_root = temp.path().join("locks");
    crate::create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let joint = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    let mut state = metrics_state("service-secret");
    state.joint_authority_store = Some(joint.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let server =
        tokio::spawn(async move { axum::serve(listener, super::build_router(state)).await });

    tokio::task::spawn_blocking(move || {
        let store = build_remote_budget_store(&url, "service-secret")?;
        let revocation_set =
            CanonicalRevocationSet::canonicalize(vec!["denied-composite".to_string()])?;
        let request = |hold_id: &str, operation_id: &str| BudgetAuthorizeHoldRequest {
            capability_id: "denied-composite".to_string(),
            grant_index: 0,
            max_invocations: Some(1),
            invocation_quotas: vec![BudgetInvocationQuota {
                key: BudgetQuotaKey::grant("denied-composite", 0),
                max_invocations: 1,
            }],
            cumulative_approval: None,
            admission_binding: Some(BudgetAdmissionBinding {
                operation_id: operation_id.to_string(),
                revocation_set: revocation_set.clone(),
                authorization_artifact_digests: vec!["a".repeat(64)],
                last_observed_revocation: None,
                supplemental_verifier_id: None,
                supplemental_verifier_config_digest: None,
                supplemental_authorization_artifact_digest: None,
                supplemental_authorization_expires_at: None,
            }),
            requested_exposure_units: 10,
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(20),
            hold_id: Some(hold_id.to_string()),
            event_id: Some(format!("{hold_id}:authorize")),
            authority: None,
        };
        assert!(matches!(
            store.authorize_budget_hold(request("denied-prefill", "prefill-operation"))?,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let cached_before = store
            .get_usage("denied-composite", 0)?
            .ok_or_else(|| std::io::Error::other("authorized usage was not cached"))?;
        let denied_request = request("denied-hold", "denied-operation");
        for decision in [
            store.authorize_budget_hold(denied_request.clone())?,
            store.authorize_budget_hold(denied_request)?,
        ] {
            let BudgetAuthorizeHoldDecision::Denied(denied) = decision else {
                return Err(std::io::Error::other("exhausted quota was not denied").into());
            };
            assert_eq!(denied.invocation_count_after, 1);
            assert_eq!(denied.committed_cost_units_after, 10);
        }
        let cached_after = store
            .get_usage("denied-composite", 0)?
            .ok_or_else(|| std::io::Error::other("authorized cache disappeared"))?;
        assert_eq!(cached_after.seq, cached_before.seq);
        assert_eq!(
            cached_after.invocation_count,
            cached_before.invocation_count
        );
        assert_eq!(
            cached_after.total_cost_exposed,
            cached_before.total_cost_exposed
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;

    let event = joint
        .budget_store()
        .mutation_event_for_event_id("denied-hold:authorize")?
        .ok_or_else(|| std::io::Error::other("denial event was not durable"))?;
    assert!(event.usage_seq.is_none());
    assert_eq!(event.invocation_count_after, 1);
    assert_eq!(event.total_cost_exposed_after, 10);
    assert_eq!(
        joint
            .budget_store()
            .list_mutation_events(10, Some("denied-composite"), Some(0))?
            .into_iter()
            .filter(|event| event.event_id == "denied-hold:authorize")
            .count(),
        1
    );
    server.abort();
    Ok(())
}

/// A scrape presenting the configured service token is served (200).
#[tokio::test]
async fn trust_control_metrics_accepts_valid_service_token() {
    let state = metrics_state("service-secret");
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    let response = handle_trust_control_metrics(State(state), headers).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn v1_lifecycle_uses_joint_store_when_legacy_handle_is_mismatched(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    crate::create_private_directory(temp.path())?;
    let database = temp.path().join("joint.sqlite3");
    let lock_root = temp.path().join("locks");
    crate::create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let joint = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    let legacy = Arc::new(SqliteBudgetStore::open(
        temp.path().join("legacy-budget.sqlite3"),
    )?);
    let legacy_revocations = Arc::new(SqliteRevocationStore::open(
        temp.path().join("legacy-revocations.sqlite3"),
    )?);
    let fence = joint.mutation_fence();
    let authority = BudgetEventAuthority {
        authority_id: fence.store_uuid,
        lease_id: fence.lease_id,
        lease_epoch: fence.owner_epoch,
    };
    let capability_id = "joint-capability";
    let hold_id = "joint-hold";
    let quota = BudgetInvocationQuota {
        key: BudgetQuotaKey::grant(capability_id, 0),
        max_invocations: 1,
    };
    let joint_budget = joint.budget_store();
    let decision = joint_budget.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: capability_id.to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: vec![quota],
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: "joint-operation".to_string(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec![capability_id.to_string()])?,
            authorization_artifact_digests: vec!["a".repeat(64)],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 10,
        max_cost_per_invocation: Some(10),
        max_total_cost_units: Some(10),
        hold_id: Some(hold_id.to_string()),
        event_id: Some("joint-hold:authorize".to_string()),
        authority: Some(authority),
    })?;
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    let mut state = metrics_state("service-secret");
    state.joint_authority_store = Some(joint.clone());
    state.budget_store = Some(legacy.clone());
    state.revocation_store = Some(legacy_revocations.clone());
    state
        .revocation_store()
        .map_err(|_| std::io::Error::other("joint revocation store was unavailable"))?
        .revoke("joint-revocation")?;
    assert!(
        joint
            .revocation_store()
            .observe_revocation("joint-revocation")?
            .revoked
    );
    assert!(
        !legacy_revocations
            .observe_revocation("joint-revocation")?
            .revoked
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    let response = handle_capture_invocation(
        State(state),
        headers,
        Json(CaptureInvocationRequest {
            capability_id: capability_id.to_string(),
            grant_index: 0,
            hold_id: hold_id.to_string(),
            event_id: "joint-hold:capture".to_string(),
        }),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let response: CaptureInvocationResponse = serde_json::from_slice(&body)?;
    let projection = response
        .structured_projection
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing structured projection"))?;
    let event_commit = projection
        .projection
        .metadata
        .budget_commit_index
        .ok_or_else(|| std::io::Error::other("missing capture event commit"))?;
    assert_ne!(response.usage_seq, Some(event_commit));
    assert_eq!(
        response
            .budget_authority
            .as_ref()
            .and_then(|authority| authority.budget_commit_index),
        Some(event_commit)
    );
    assert!(legacy.get_usage(capability_id, 0)?.is_none());
    assert_eq!(
        joint_budget
            .get_usage(capability_id, 0)?
            .map(|usage| usage.invocation_count),
        Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn v1_lifecycle_uses_current_joint_epoch_after_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    crate::create_private_directory(temp.path())?;
    let database = temp.path().join("joint-restart.sqlite3");
    let lock_root = temp.path().join("locks");
    crate::create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let first_fence = first.mutation_fence();
    let capability_id = "restart-capability";
    let hold_id = "restart-hold";
    let first_budget = first.budget_store();
    assert!(matches!(
        first_budget.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: capability_id.to_string(),
            grant_index: 0,
            max_invocations: Some(1),
            invocation_quotas: vec![BudgetInvocationQuota {
                key: BudgetQuotaKey::grant(capability_id, 0),
                max_invocations: 1,
            }],
            cumulative_approval: None,
            admission_binding: Some(BudgetAdmissionBinding {
                operation_id: "restart-operation".to_string(),
                revocation_set: CanonicalRevocationSet::canonicalize(vec![
                    capability_id.to_string(),
                ])?,
                authorization_artifact_digests: vec!["b".repeat(64)],
                last_observed_revocation: None,
                supplemental_verifier_id: None,
                supplemental_verifier_config_digest: None,
                supplemental_authorization_artifact_digest: None,
                supplemental_authorization_expires_at: None,
            }),
            requested_exposure_units: 10,
            max_cost_per_invocation: Some(10),
            max_total_cost_units: Some(10),
            hold_id: Some(hold_id.to_string()),
            event_id: Some("restart-hold:authorize".to_string()),
            authority: Some(BudgetEventAuthority {
                authority_id: first_fence.store_uuid.clone(),
                lease_id: first_fence.lease_id,
                lease_epoch: first_fence.owner_epoch,
            }),
        })?,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    drop(first_budget);
    drop(first);

    let restarted = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    let restarted_fence = restarted.mutation_fence();
    assert_eq!(restarted_fence.store_uuid, first_fence.store_uuid);
    assert!(restarted_fence.owner_epoch > first_fence.owner_epoch);
    let mut state = metrics_state("service-secret");
    state.joint_authority_store = Some(restarted);
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    let response = handle_capture_invocation(
        State(state),
        headers,
        Json(CaptureInvocationRequest {
            capability_id: capability_id.to_string(),
            grant_index: 0,
            hold_id: hold_id.to_string(),
            event_id: "restart-hold:capture".to_string(),
        }),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let response: CaptureInvocationResponse = serde_json::from_slice(&body)?;
    let projection = response
        .structured_projection
        .ok_or_else(|| std::io::Error::other("missing structured projection"))?;
    assert_eq!(
        projection
            .projection
            .metadata
            .authority
            .map(|authority| authority.lease_epoch),
        Some(restarted_fence.owner_epoch)
    );
    Ok(())
}

/// Building the trust-control serve router must seed the fixed alert-pack
/// label sets, so a fresh, healthy-but-quiet control plane renders the
/// fail-open / dispatch-failure / capability-revocation families at zero and
/// the shipped absent_over_time backstops fire only on a true scrape gap, not
/// on a control plane that simply has not had an event yet.
#[tokio::test]
async fn build_router_seeds_alert_pack_series_for_absent_over_time_backstops() {
    let state = metrics_state("service-secret");
    let _router = super::build_router(state);

    let mut body = String::new();
    chio_metrics_spec::runtime::render_alert_pack_families(&mut body);
    assert!(
            body.contains("chio_dispatch_failure_total{surface=\"http_authority\",outcome=\"error\"}"),
            "the dispatch-failure family must be present at zero after building the serve router: {body}"
        );
    assert!(
        body.contains("chio_fail_open_suspected_total{surface=\"tower\"}"),
        "the fail-open family must be present at zero after building the serve router: {body}"
    );
    assert!(
            body.contains("chio_capability_revocation_lag_seconds"),
            "the capability-revocation-lag family must be present after building the serve router: {body}"
        );
}

#[tokio::test]
async fn captured_before_dispatch_cancellation_route_is_not_served(
) -> Result<(), Box<dyn std::error::Error>> {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let request = Request::builder()
            .method("POST")
            .uri("/v1/budgets/cancel-captured-before-dispatch")
            .header(AUTHORIZATION, "Bearer service-secret")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"capabilityId":"cap-budget","grantIndex":0,"holdId":"hold-budget","eventId":"hold-budget:cancel"}"#,
            ))?;
    let response = super::build_router(metrics_state("service-secret"))
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// A stream receipt embeds one digest per retained chunk, so a valid receipt
/// append routinely exceeds the service-wide 1 MiB request cap. The two
/// receipt-append routes carry their own larger body limit so replicating or
/// importing such a receipt reaches the handler instead of being rejected with
/// 413, while a route without the override stays capped: the relaxation is
/// route-specific, not a global loosening.
#[tokio::test]
async fn receipt_append_routes_accept_bodies_above_the_service_body_cap() {
    use axum::body::Body;
    use axum::http::Request;
    use chio_http_serve::{apply_server_hygiene, ServeHygieneConfig};
    use tower::ServiceExt;

    // Mirror the service-wide 1 MiB body cap the trust-control serve site
    // applies around the router.
    let hygiene = ServeHygieneConfig {
        max_body_bytes: Some(1024 * 1024),
        request_timeout: None,
        ..ServeHygieneConfig::default()
    };
    let build = || apply_server_hygiene(super::build_router(metrics_state("secret")), &hygiene);

    // Over the 1 MiB service cap but well under the receipt cap. The bytes are
    // not a valid receipt, so the handler's own decode still rejects them, but
    // NOT with 413: the point is the larger route limit lets the request reach
    // the handler at all.
    let oversized = vec![b'x'; 2 * 1024 * 1024];

    for path in [TOOL_RECEIPTS_PATH, CHILD_RECEIPTS_PATH] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(oversized.clone()))
            .test_unwrap();
        let response = build().oneshot(request).await.test_unwrap();
        assert_ne!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{path} must accept a receipt body above the 1 MiB service cap"
        );
    }

    let request = Request::builder()
        .method("POST")
        .uri(ISSUE_CAPABILITY_PATH)
        .header("content-type", "application/json")
        .body(Body::from(oversized))
        .test_unwrap();
    let response = build().oneshot(request).await.test_unwrap();
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a route without the receipt-append override must still cap at 1 MiB"
    );
}
