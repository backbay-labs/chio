#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_views_hide_revoked_terminal_authorities() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority, market_config());
    deployment.seed_and_activate(&state).await?;
    let search_uri = format!("/v1/findings/search?contextSha256={HEX64}&limit=50");
    let admission_uri = format!("/v1/findings/{}/admission", deployment.web.finding_id);

    let (status, body) = send(&state, public_get(&search_uri)?).await?;
    assert_eq!(status, StatusCode::OK);
    let rows = json_body(&body)?;
    let live_row = rows["results"]
        .as_array()
        .ok_or_else(|| missing("search results array"))?
        .iter()
        .find(|row| row["findingId"] == serde_json::json!(deployment.web.finding_id))
        .ok_or_else(|| missing("activated finding missing from search"))?;
    assert!(live_row["admission"].is_object());
    let (status, _) = send(&state, public_get(&admission_uri)?).await?;
    assert_eq!(status, StatusCode::OK);

    for authority_id in [
        deployment
            .web
            .admission
            .body
            .purchase_authority
            .authority_id
            .clone(),
        deployment
            .web
            .admission
            .body
            .failed_delivery_authority
            .authority_id
            .clone(),
    ] {
        state.finding_authority_status_resolver = Some(Arc::new(
            TestTerminalAuthorityStatusResolver::revoked(&authority_id),
        ));
        let (status, body) = send(&state, public_get(&search_uri)?).await?;
        assert_eq!(status, StatusCode::OK);
        let rows = json_body(&body)?;
        let revoked_row = rows["results"]
            .as_array()
            .ok_or_else(|| missing("search results array"))?
            .iter()
            .find(|row| row["findingId"] == serde_json::json!(deployment.web.finding_id))
            .ok_or_else(|| missing("activated finding missing from search"))?;
        assert!(
            revoked_row["admission"].is_null(),
            "revoked terminal authority {authority_id} remained discoverable"
        );
        let (status, _) = send(&state, public_get(&admission_uri)?).await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    Ok(())
}

fn deny_reason(response: &ToolCallResponse) -> String {
    response.reason.clone().unwrap_or_default()
}

fn assert_denied_with(response: &ToolCallResponse, fragment: &str) {
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    let reason = deny_reason(response);
    assert!(
        reason.contains(fragment),
        "expected {fragment:?} in {reason:?}"
    );
}

struct FixedStatusAdmissionClock(u64);

impl crate::trust_control::finding_status_verifier::FindingStatusAdmissionClock
    for FixedStatusAdmissionClock
{
    fn now_unix_secs(&self) -> Result<u64, String> {
        Ok(self.0)
    }
}

struct FinalBoundaryStatusAdmissionClock {
    fresh_now: u64,
    final_now: u64,
    calls: AtomicU64,
}

impl crate::trust_control::finding_status_verifier::FindingStatusAdmissionClock
    for FinalBoundaryStatusAdmissionClock
{
    fn now_unix_secs(&self) -> Result<u64, String> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(self.fresh_now)
        } else {
            Ok(self.final_now)
        }
    }
}

struct FinalBoundaryRetractionClock {
    fresh_now: u64,
    final_now: u64,
    calls: AtomicU64,
}

impl chio_guards::finding_retraction::FindingRetractionClock
    for FinalBoundaryRetractionClock
{
    fn now_unix_secs(
        &self,
    ) -> Result<u64, chio_guards::finding_retraction::FindingRetractionResolveError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) < 2 {
            Ok(self.fresh_now)
        } else {
            Ok(self.final_now)
        }
    }
}

struct RetractionBeforeCacheReleaseClock {
    now: u64,
    calls: AtomicU64,
    store: SqliteFindingStatusStore,
    feed_id: String,
    operator_id: String,
    finding_id: String,
    intent_id: String,
    intent_bytes: Vec<u8>,
    inclusion_deadline: u64,
}

impl chio_guards::finding_retraction::FindingRetractionClock
    for RetractionBeforeCacheReleaseClock
{
    fn now_unix_secs(
        &self,
    ) -> Result<u64, chio_guards::finding_retraction::FindingRetractionResolveError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 2 {
            self.store
                .issue_retraction_intent(&chio_store_sqlite::FindingRetractionIntentInput {
                    intent_id: &self.intent_id,
                    feed_id: &self.feed_id,
                    operator_id: &self.operator_id,
                    finding_id: &self.finding_id,
                    source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
                    intent_bytes: &self.intent_bytes,
                    issued_at: self.now,
                    inclusion_deadline: self.inclusion_deadline,
                    created_at: self.now,
                })
                .map_err(|error| {
                    chio_guards::finding_retraction::FindingRetractionResolveError::ClockUnavailable(
                        error.to_string(),
                    )
                })?;
        }
        Ok(self.now)
    }
}

struct RetractionOnRefreshClock {
    now: u64,
    calls: AtomicU64,
    fire_on_call: u64,
    store: SqliteFindingStatusStore,
    feed_id: String,
    operator_id: String,
    finding_id: String,
    intent_id: String,
    intent_bytes: Vec<u8>,
    inclusion_deadline: u64,
}

impl crate::trust_control::finding_status_verifier::FindingStatusAdmissionClock
    for RetractionOnRefreshClock
{
    fn now_unix_secs(&self) -> Result<u64, String> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == self.fire_on_call {
            self.store
                .issue_retraction_intent(&chio_store_sqlite::FindingRetractionIntentInput {
                    intent_id: &self.intent_id,
                    feed_id: &self.feed_id,
                    operator_id: &self.operator_id,
                    finding_id: &self.finding_id,
                    source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
                    intent_bytes: &self.intent_bytes,
                    issued_at: self.now,
                    inclusion_deadline: self.inclusion_deadline,
                    created_at: self.now,
                })
                .map_err(|error| error.to_string())?;
        }
        Ok(self.now)
    }
}

struct RejectCurrentRecoveryStatusVerifier {
    inner: MarketFindingStatusVerifier,
}

impl chio_kernel::finding_purchase::FindingStatusProofVerifier
    for RejectCurrentRecoveryStatusVerifier
{
    fn verify_status_proof(
        &self,
        view: &chio_kernel::finding_purchase::FindingStatusProofContextView<'_>,
    ) -> Result<
        chio_kernel::finding_purchase::VerifiedFindingStatusProof,
        chio_kernel::finding_denial::FindingDenial,
    > {
        chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_proof(
            &self.inner,
            view,
        )
    }

    fn verify_status_admission(
        &self,
        view: &chio_kernel::finding_purchase::FindingStatusProofContextView<'_>,
        verified: &chio_kernel::finding_purchase::VerifiedFindingStatusProof,
        now_unix_secs: u64,
    ) -> Result<(), chio_kernel::finding_denial::FindingDenial> {
        chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_admission(
            &self.inner,
            view,
            verified,
            now_unix_secs,
        )
    }

    fn verify_current_status_admission(
        &self,
        _view: &chio_kernel::finding_purchase::FindingCurrentStatusContextView<'_>,
        _now_unix_secs: u64,
    ) -> Result<(), chio_kernel::finding_denial::FindingDenial> {
        Err(chio_kernel::finding_denial::FindingDenial::status_denied(
            "finding recovery became ineligible after dispatch",
        ))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_purchase_without_status_verifier_denies_before_effects() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: false,
        ..LaneOptions::standard()
    })
    .await?;
    let denied =
        lane.reveal_without_status("m6-missing-status-verifier", "m6-missing-status-nonce")?;
    assert_denied_with(&denied, "configured kernel verifier");
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_status_retraction() -> TestResult {
    run_finding_status_retraction().await
}

pub(super) async fn run_finding_status_retraction() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: true,
        publish_status_proof: false,
        ..LaneOptions::standard()
    })
    .await?;
    let config = market_config();
    let status_store = lane.authority.finding_status_store();
    let publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let now = unix_timestamp_now();
    assert!(
        status_store
            .list_non_inclusion_enrollment_candidates(
                &config.status_feed_operator_ref,
                now,
                200,
            )?
            .is_empty(),
        "activation must enroll the admission's first non-inclusion proof"
    );
    let enrolled = status_store
        .get_latest_proof(
            &config.status_feed_operator_ref,
            &lane.deployment.web.finding_id,
        )?
        .ok_or("activation-enrolled non-inclusion proof is durable")?;
    let live = publisher.publish_non_inclusion(&lane.deployment.web.finding_id, &[], now)?;
    assert_eq!(live.proof_sha256, enrolled.proof_sha256);
    assert!(status_store
        .list_non_inclusion_enrollment_candidates(
            &config.status_feed_operator_ref,
            now,
            200,
        )?
        .is_empty());
    let duplicate_live =
        publisher.publish_non_inclusion(&lane.deployment.web.finding_id, &[], now + 1)?;
    assert_eq!(duplicate_live.proof_sha256, live.proof_sha256);
    assert_eq!(duplicate_live.checked_at, live.checked_at);
    let other_live_finding = sha256_hex(b"m6-independent-live-finding");
    let other_live = publisher.publish_non_inclusion(&other_live_finding, &[], now)?;
    assert_eq!(
        other_live.map_epoch, live.map_epoch,
        "point proofs over an unchanged map reuse the signed epoch"
    );
    assert_eq!(
        status_store.get_feed_floor(&config.status_feed_operator_ref)?.map_epoch,
        live.map_epoch
    );
    assert_eq!(
        status_store
            .get_latest_proof(
                &config.status_feed_operator_ref,
                &lane.deployment.web.finding_id,
            )?
            .ok_or("the first point proof remains current")?
            .epoch_id,
        live.epoch_id
    );
    let live_b64 = STANDARD.encode(&live.proof_bytes);
    let delivered = lane.reveal_with_status(
        &lane.purchase,
        &live_b64,
        "m6-live-reveal-1",
        "m6-live-nonce-1",
    )?;
    assert_eq!(delivered.verdict, Verdict::Allow, "{:?}", delivered.reason);
    let delivery = finding_delivery_block(&delivered)?;
    assert!(delivery.status_proof.is_some());
    buyer_memory_write(
        &lane.deployment,
        &delivered.receipt,
        &lane.buyer,
        &lane.authority,
        status_store.clone(),
    )?;

    let provenance: Arc<dyn chio_kernel::MemoryProvenanceStore> =
        Arc::new(chio_store_sqlite::SqliteMemoryProvenanceStore::open(
            &lane.deployment.memory_provenance_db,
        )?);
    let receipts: Arc<dyn ReceiptStore> = Arc::new(chio_store_sqlite::SqliteReceiptStore::open(
        &lane.deployment.receipt_db,
    )?);
    let resolver =
        crate::trust_control::finding_retraction_resolver::sqlite_finding_retraction_resolver(
            "resolver/venue-wedge",
            &config,
            provenance,
            receipts,
            status_store.clone(),
        )?;
    let live_resolution =
        resolver.resolve(chio_guards::finding_retraction::FindingRetractionQuery {
            store: "purchased-findings",
            key: &lane.deployment.web.finding_id,
        })?;
    assert_eq!(
        live_resolution.value,
        chio_guards::finding_retraction::FindingStatusValue::Live
    );
    let guard = chio_guards::MemoryGovernanceGuard::with_config_and_retraction_resolver(
        chio_guards::MemoryGovernanceConfig {
            finding_retraction: Some(chio_guards::FindingRetractionGuardConfig {
                resolver_id: "resolver/venue-wedge".to_owned(),
                feed_id: config.status_feed_operator_ref.clone(),
            }),
            ..chio_guards::MemoryGovernanceConfig::default()
        },
        Arc::clone(&resolver),
    )?;
    let mut holder_kernel = ChioKernel::new(kernel_config(keypair(42), Vec::new()));
    holder_kernel.add_guard(Box::new(guard));
    holder_kernel.register_tool_server(Box::new(BuyerMemoryServer));
    let read_capability = holder_kernel.issue_capability(
        &lane.buyer.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "buyer-memory".to_owned(),
                tool_name: "memory_read".to_owned(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        300,
    )?;
    let memory_read_request = |request_id: &str| ToolCallRequest {
        request_id: request_id.to_owned(),
        capability: read_capability.clone(),
        tool_name: "memory_read".to_owned(),
        server_id: "buyer-memory".to_owned(),
        agent_id: read_capability.subject.to_hex(),
        arguments: serde_json::json!({
            "collection": "purchased-findings",
            "id": lane.deployment.web.finding_id,
        }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let live_read =
        holder_kernel.evaluate_tool_call_blocking(&memory_read_request("m6-holder-live-read"))?;
    assert_eq!(live_read.verdict, Verdict::Allow, "{:?}", live_read.reason);

    // A second independent venue instance supplies a fresh one-shot purchase
    // for the pending and retracted admission checks. The live purchase above
    // must retain its seller exposure for the full liability horizon, so this
    // test cannot recycle that allocation merely to reach the status gate.
    let mut status_lane = open_lane(LaneOptions {
        install_status_verifier: true,
        ..LaneOptions::standard()
    })
    .await?;
    let status_gate_store = status_lane.authority.finding_status_store();
    let status_gate_publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_gate_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let status_gate_now = unix_timestamp_now();

    let intent_id = sha256_hex(b"m6-voluntary-retraction-intent");
    let intent_bytes = canonical_json_bytes(&serde_json::json!({
        "finding_id": lane.deployment.web.finding_id,
        "reason": "seller_voluntary_retraction",
        "schema": "chio.finding.voluntary-retraction.v1",
    }))?;
    let primary_intent_now = unix_timestamp_now().max(now);
    let intent = chio_store_sqlite::FindingRetractionIntentInput {
        intent_id: &intent_id,
        feed_id: &config.status_feed_operator_ref,
        operator_id: &config.status_feed_operator.authority.authority_id,
        finding_id: &lane.deployment.web.finding_id,
        source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
        intent_bytes: &intent_bytes,
        issued_at: primary_intent_now,
        inclusion_deadline: primary_intent_now
            + config.status_feed_service_bond.inclusion_sla_secs,
        created_at: primary_intent_now,
    };
    assert_eq!(
        status_store.issue_retraction_intent(&intent)?,
        chio_store_sqlite::FindingStatusWriteOutcome::Inserted
    );
    assert_eq!(
        status_store.issue_retraction_intent(&intent)?,
        chio_store_sqlite::FindingStatusWriteOutcome::ExactReplay
    );
    assert!(publisher
        .publish_non_inclusion(
            &lane.deployment.web.finding_id,
            &[],
            primary_intent_now,
        )
        .is_err());

    let hook_store = status_gate_store.clone();
    let hook_intent_id = intent_id.clone();
    let hook_feed_id = config.status_feed_operator_ref.clone();
    let hook_operator_id = config.status_feed_operator.authority.authority_id.clone();
    let hook_finding_id = lane.deployment.web.finding_id.clone();
    let hook_intent_bytes = intent_bytes.clone();
    let status_gate_intent_now = unix_timestamp_now().max(status_gate_now);
    let hook_inclusion_sla_secs = config.status_feed_service_bond.inclusion_sla_secs;
    let status_gate_live = status_gate_publisher.publish_non_inclusion(
        &status_lane.deployment.web.finding_id,
        &[],
        status_gate_intent_now,
    )?;
    let status_gate_live_b64 = STANDARD.encode(&status_gate_live.proof_bytes);
    status_lane
        .kernel
        .set_payment_adapter(Box::new(ReversibleHoldAdapter {
            calls: status_lane.calls.clone(),
            authorize_hook: Some(Arc::new(move || {
                let hook_now = unix_timestamp_now();
                hook_store
                    .issue_retraction_intent(&chio_store_sqlite::FindingRetractionIntentInput {
                        intent_id: &hook_intent_id,
                        feed_id: &hook_feed_id,
                        operator_id: &hook_operator_id,
                        finding_id: &hook_finding_id,
                        source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
                        intent_bytes: &hook_intent_bytes,
                        issued_at: hook_now,
                        inclusion_deadline: hook_now + hook_inclusion_sla_secs,
                        created_at: hook_now,
                    })
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            })),
        }));

    let pending = status_lane.reveal_with_status(
        &status_lane.purchase,
        &status_gate_live_b64,
        "m6-pending-reveal-2",
        "m6-pending-nonce-2",
    )?;
    assert_denied_with(&pending, "pending");
    let pending_intent = status_gate_store
        .get_retraction_intent(&intent_id)?
        .ok_or("the payment-boundary hook retains the pending retraction")?;
    assert_eq!(
        pending_intent.state,
        chio_store_sqlite::FindingRetractionIntentState::DispatchEligible
    );
    assert_eq!(status_lane.calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(status_lane.calls.releases.load(Ordering::SeqCst), 1);
    assert_eq!(status_lane.invocations.load(Ordering::SeqCst), 0);

    let status_gate_retraction_now = unix_timestamp_now().max(pending_intent.issued_at);
    let included = status_gate_publisher.publish_retraction(
        &intent_id,
        &[],
        status_gate_retraction_now,
    )?;
    let included_b64 = STANDARD.encode(&included.proof_bytes);
    let duplicate = status_gate_publisher.publish_retraction(
        &intent_id,
        &[],
        status_gate_retraction_now,
    )?;
    assert_eq!(duplicate.proof_sha256, included.proof_sha256);
    let retracted = status_lane.reveal_with_status(
        &status_lane.purchase,
        &included_b64,
        "m6-retracted-reveal-2",
        "m6-retracted-nonce-2",
    )?;
    assert_denied_with(&retracted, "retracted");
    let rollback = status_lane.reveal_with_status(
        &status_lane.purchase,
        &status_gate_live_b64,
        "m6-rollback-reveal-2",
        "m6-rollback-nonce-2",
    )?;
    assert_denied_with(&rollback, "rollback");

    let second_finding_id = sha256_hex(b"m6-second-retracted-finding");
    let second_intent_id = sha256_hex(b"m6-second-retraction-intent");
    let second_intent_bytes = canonical_json_bytes(&serde_json::json!({
        "finding_id": second_finding_id,
        "reason": "seller_voluntary_retraction",
        "schema": "chio.finding.voluntary-retraction.v1",
    }))?;
    let second_intent_now = unix_timestamp_now().max(status_gate_retraction_now);
    status_gate_store.issue_retraction_intent(
        &chio_store_sqlite::FindingRetractionIntentInput {
            intent_id: &second_intent_id,
            feed_id: &config.status_feed_operator_ref,
            operator_id: &config.status_feed_operator.authority.authority_id,
            finding_id: &second_finding_id,
            source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
            intent_bytes: &second_intent_bytes,
            issued_at: second_intent_now,
            inclusion_deadline: second_intent_now
                + config.status_feed_service_bond.inclusion_sla_secs,
            created_at: second_intent_now,
        },
    )?;
    let second_publish_now = unix_timestamp_now().max(second_intent_now + 1);
    let second_included = status_gate_publisher.publish_retraction(
        &second_intent_id,
        &[],
        second_publish_now,
    )?;
    let refresh_candidates = status_gate_store.list_publication_candidates(
        &config.status_feed_operator_ref,
        &config.status_feed_operator.authority.key_hex,
        &config.status_feed_operator.authorization_sha256,
        second_publish_now,
        200,
    )?;
    assert!(!refresh_candidates
        .iter()
        .any(|candidate| candidate.intent_id == intent_id));
    assert!(status_gate_store
        .get_latest_proof(&config.status_feed_operator_ref, &lane.deployment.web.finding_id)?
        .is_none());
    let refreshed_included =
        status_gate_publisher.publish_retraction(&intent_id, &[], second_publish_now)?;
    assert_eq!(refreshed_included.map_epoch, second_included.map_epoch);
    assert_eq!(
        refreshed_included.kind,
        chio_store_sqlite::FindingStatusProofKind::Inclusion
    );
    assert!(!status_gate_store
        .list_publication_candidates(
            &config.status_feed_operator_ref,
            &config.status_feed_operator.authority.key_hex,
            &config.status_feed_operator.authorization_sha256,
            second_publish_now,
            200,
        )?
        .iter()
        .any(|candidate| candidate.intent_id == intent_id));

    let anchor_refresh_at = second_publish_now + 1;
    assert!(!status_gate_publisher.epoch_refresh_required(&[], anchor_refresh_at)?);
    let prior_invalid_refresh_epoch = status_gate_store
        .get_feed_floor(&config.status_feed_operator_ref)?
        .map_epoch;
    let invalid_anchors = (0..17)
        .map(|index| format!("anchor://finding-status/invalid-{index}"))
        .collect::<Vec<_>>();
    let invalid_refresh = status_gate_publisher
        .publish_epoch_refresh(&invalid_anchors, anchor_refresh_at)
        .err()
        .ok_or("an invalid root-only epoch advanced the floor")?;
    assert!(invalid_refresh.contains("anchor_refs"));
    assert_eq!(
        status_gate_store
            .get_feed_floor(&config.status_feed_operator_ref)?
            .map_epoch,
        prior_invalid_refresh_epoch
    );
    let finalized_anchors = vec!["anchor://finding-status/finalized-1".to_owned()];
    assert!(status_gate_publisher
        .epoch_refresh_required(&finalized_anchors, anchor_refresh_at)?);
    let prior_anchor_epoch = status_gate_store
        .get_feed_floor(&config.status_feed_operator_ref)?
        .map_epoch;
    let anchored_epoch = status_gate_publisher
        .publish_epoch_refresh(&finalized_anchors, anchor_refresh_at)?;
    assert_eq!(anchored_epoch.body.map_epoch, prior_anchor_epoch + 1);
    assert_eq!(anchored_epoch.body.anchor_refs, finalized_anchors);
    assert!(!status_gate_store
        .list_publication_candidates(
            &config.status_feed_operator_ref,
            &config.status_feed_operator.authority.key_hex,
            &config.status_feed_operator.authorization_sha256,
            anchor_refresh_at,
            200,
        )?
        .iter()
        .any(|candidate| candidate.intent_id == intent_id));

    let mut rotated_operator = config.status_feed_operator.clone();
    rotated_operator.authority.key_hex = keypair(46).public_key().to_hex();
    rotated_operator.authority.key_epoch += 1;
    rotated_operator.authorization_sha256 = sha256_hex(b"rotated-status-operator-authorization");
    let rotated_publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_gate_store.clone(),
            rotated_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(46),
            config.status_max_epoch_age_secs,
        )?;
    let prior_epoch = status_gate_store
        .get_feed_floor(&config.status_feed_operator_ref)?
        .map_epoch;
    let rotation_now = unix_timestamp_now().max(anchor_refresh_at + 1);
    let rotated = rotated_publisher.publish_non_inclusion(
        &sha256_hex(b"m6-live-after-operator-rotation"),
        &[],
        rotation_now,
    )?;
    assert_eq!(rotated.map_epoch, prior_epoch + 1);
    assert_eq!(
        status_gate_store
            .get_current_epoch(&config.status_feed_operator_ref)?
            .operator_key_epoch,
        rotated_operator.authority.key_epoch
    );

    let primary_retraction_now = unix_timestamp_now().max(primary_intent_now);
    publisher.publish_retraction(&intent_id, &[], primary_retraction_now)?;
    let delivery_status = delivery
        .status_proof
        .as_ref()
        .ok_or_else(|| missing("delivery status proof"))?;
    let current_status_verifier = MarketFindingStatusVerifier::new(
        config.status_feed_operator.clone(),
        config.status_feed_service_bond.clone(),
        config.status_max_epoch_age_secs,
        status_store.clone(),
    )?;
    let write_status_error = match chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_current_status_admission(
        &current_status_verifier,
        &chio_kernel::finding_purchase::FindingCurrentStatusContextView {
            expected_finding_id: &lane.deployment.web.finding_id,
            expected_feed_id: &delivery_status.feed_id,
            minimum_map_epoch: delivery_status.map_epoch,
            minimum_non_inclusion_checked_at: delivery_status.non_inclusion_checked_at,
        },
        primary_retraction_now,
    ) {
        Ok(()) => return Err(missing("retracted Finding memory-write denial")),
        Err(error) => error,
    };
    assert!(write_status_error.detail().contains("retracted"));
    let resolved = resolver.resolve(chio_guards::finding_retraction::FindingRetractionQuery {
        store: "purchased-findings",
        key: &lane.deployment.web.finding_id,
    })?;
    assert_eq!(
        resolved.value,
        chio_guards::finding_retraction::FindingStatusValue::Retracted
    );
    let guarded = holder_kernel
        .evaluate_tool_call_blocking(&memory_read_request("m6-holder-retracted-read"))?;
    assert_eq!(guarded.verdict, Verdict::Deny);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_status_freshness_rechecks_at_final_clock_samples() -> TestResult {
    let admission_lane = open_lane(LaneOptions {
        install_status_verifier: true,
        publish_status_proof: false,
        ..LaneOptions::standard()
    })
    .await?;
    let config = market_config();
    let admission_store = admission_lane.authority.finding_status_store();
    let admission_publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            admission_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let now = unix_timestamp_now();
    let live = admission_publisher.publish_non_inclusion(
        &admission_lane.deployment.web.finding_id,
        &[],
        now,
    )?;
    let stale_at_final_decision = now + config.status_max_epoch_age_secs + 1;
    let refreshed_verifier = MarketFindingStatusVerifier::new_with_clock(
        config.status_feed_operator.clone(),
        config.status_feed_service_bond.clone(),
        config.status_max_epoch_age_secs,
        admission_store,
        Arc::new(FinalBoundaryStatusAdmissionClock {
            fresh_now: now + 1,
            final_now: stale_at_final_decision,
            calls: AtomicU64::new(0),
        }),
    )?;
    let live_b64 = STANDARD.encode(&live.proof_bytes);
    let live_view = chio_kernel::finding_purchase::FindingStatusProofContextView {
        proof_b64: &live_b64,
        expected_finding_id: &admission_lane.deployment.web.finding_id,
        expected_feed_id: &config.status_feed_operator_ref,
    };
    let verified_live =
        chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_proof(
            &refreshed_verifier,
            &live_view,
        )?;
    let stale_admission =
        chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_admission(
            &refreshed_verifier,
            &live_view,
            &verified_live,
            now,
        )
        .err()
        .ok_or("final status admission clock accepted an expired epoch")?;
    assert!(
        stale_admission.detail().contains("stale") || stale_admission.detail().contains("freshness"),
        "unexpected refreshed-time rejection: {stale_admission}"
    );

    let cache_lane = open_lane(LaneOptions {
        install_status_verifier: true,
        publish_status_proof: false,
        ..LaneOptions::standard()
    })
    .await?;
    let cache_store = cache_lane.authority.finding_status_store();
    let cache_publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            cache_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let cache_now = unix_timestamp_now();
    cache_publisher.publish_non_inclusion(
        &cache_lane.deployment.web.finding_id,
        &[],
        cache_now,
    )?;
    let cache = crate::trust_control::finding_retraction_resolver::SqliteFindingStatusCache::new(
        &config,
        cache_store,
        Arc::new(FinalBoundaryRetractionClock {
            fresh_now: cache_now + 1,
            final_now: cache_now + config.status_max_epoch_age_secs + 1,
            calls: AtomicU64::new(0),
        }),
    )?;
    let stale_cache = chio_guards::finding_retraction::FindingStatusCache::authenticated_status(
        &cache,
        &cache_lane.deployment.web.finding_id,
    )
    .err()
    .ok_or("final cache clock accepted an expired epoch")?;
    assert!(matches!(
        &stale_cache,
        chio_guards::finding_retraction::FindingRetractionResolveError::InvalidStatus(ref message)
            if message.contains("stale") || message.contains("freshness")
    ), "unexpected refreshed-cache rejection: {stale_cache:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_status_cache_rechecks_sticky_state_after_proof_verification() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: true,
        publish_status_proof: false,
        ..LaneOptions::standard()
    })
    .await?;
    let config = market_config();
    let status_store = lane.authority.finding_status_store();
    let publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let now = unix_timestamp_now();
    publisher.publish_non_inclusion(&lane.deployment.web.finding_id, &[], now)?;
    let intent_bytes = canonical_json_bytes(&serde_json::json!({
        "finding_id": lane.deployment.web.finding_id,
        "reason": "concurrent-cache-retraction",
        "schema": "chio.finding.voluntary-retraction.v1",
    }))?;
    let cache = crate::trust_control::finding_retraction_resolver::SqliteFindingStatusCache::new(
        &config,
        status_store.clone(),
        Arc::new(RetractionBeforeCacheReleaseClock {
            now,
            calls: AtomicU64::new(0),
            store: status_store,
            feed_id: config.status_feed_operator_ref.clone(),
            operator_id: config.status_feed_operator.authority.authority_id.clone(),
            finding_id: lane.deployment.web.finding_id.clone(),
            intent_id: sha256_hex(b"m6-cache-release-retraction-intent"),
            intent_bytes,
            inclusion_deadline: now + config.status_feed_service_bond.inclusion_sla_secs,
        }),
    )?;
    let error = chio_guards::finding_retraction::FindingStatusCache::authenticated_status(
        &cache,
        &lane.deployment.web.finding_id,
    )
    .err()
    .ok_or("concurrent retraction was accepted after cache proof verification")?;
    assert!(matches!(
        error,
        chio_guards::finding_retraction::FindingRetractionResolveError::StatusUnavailable(
            ref message
        ) if message.contains("changed")
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_status_admission_rechecks_sticky_state_after_proof_verification() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: true,
        publish_status_proof: false,
        ..LaneOptions::standard()
    })
    .await?;
    let config = market_config();
    let status_store = lane.authority.finding_status_store();
    let publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let now = unix_timestamp_now();
    let live = publisher.publish_non_inclusion(&lane.deployment.web.finding_id, &[], now)?;
    let live_b64 = STANDARD.encode(&live.proof_bytes);
    let live_view = chio_kernel::finding_purchase::FindingStatusProofContextView {
        proof_b64: &live_b64,
        expected_finding_id: &lane.deployment.web.finding_id,
        expected_feed_id: &config.status_feed_operator_ref,
    };
    let refresh_now = now + 1;
    let intent_bytes = canonical_json_bytes(&serde_json::json!({
        "finding_id": lane.deployment.web.finding_id,
        "reason": "concurrent-seller-retraction",
        "schema": "chio.finding.voluntary-retraction.v1",
    }))?;
    let verifier = MarketFindingStatusVerifier::new_with_clock(
        config.status_feed_operator.clone(),
        config.status_feed_service_bond.clone(),
        config.status_max_epoch_age_secs,
        status_store.clone(),
        Arc::new(RetractionOnRefreshClock {
            now: refresh_now,
            calls: AtomicU64::new(0),
            fire_on_call: 0,
            store: status_store,
            feed_id: config.status_feed_operator_ref.clone(),
            operator_id: config.status_feed_operator.authority.authority_id.clone(),
            finding_id: lane.deployment.web.finding_id.clone(),
            intent_id: sha256_hex(b"m6-concurrent-retraction-intent"),
            intent_bytes,
            inclusion_deadline: refresh_now
                + config.status_feed_service_bond.inclusion_sla_secs,
        }),
    )?;
    let verified =
        chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_proof(
            &verifier, &live_view,
        )?;
    let error = chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_admission(
        &verifier, &live_view, &verified, now,
    )
    .err()
    .ok_or("concurrent retraction was accepted after final proof verification")?;
    assert!(error.detail().contains("pending"), "unexpected rejection: {error}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_status_admission_makes_sticky_read_final_after_record_verification() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: true,
        publish_status_proof: false,
        ..LaneOptions::standard()
    })
    .await?;
    let config = market_config();
    let status_store = lane.authority.finding_status_store();
    let publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let now = unix_timestamp_now();
    let live = publisher.publish_non_inclusion(&lane.deployment.web.finding_id, &[], now)?;
    let live_b64 = STANDARD.encode(&live.proof_bytes);
    let live_view = chio_kernel::finding_purchase::FindingStatusProofContextView {
        proof_b64: &live_b64,
        expected_finding_id: &lane.deployment.web.finding_id,
        expected_feed_id: &config.status_feed_operator_ref,
    };
    let refresh_now = now + 1;
    let intent_bytes = canonical_json_bytes(&serde_json::json!({
        "finding_id": lane.deployment.web.finding_id,
        "reason": "retraction-after-record-verification",
        "schema": "chio.finding.voluntary-retraction.v1",
    }))?;
    let verifier = MarketFindingStatusVerifier::new_with_clock(
        config.status_feed_operator.clone(),
        config.status_feed_service_bond.clone(),
        config.status_max_epoch_age_secs,
        status_store.clone(),
        Arc::new(RetractionOnRefreshClock {
            now: refresh_now,
            calls: AtomicU64::new(0),
            fire_on_call: 1,
            store: status_store,
            feed_id: config.status_feed_operator_ref.clone(),
            operator_id: config.status_feed_operator.authority.authority_id.clone(),
            finding_id: lane.deployment.web.finding_id.clone(),
            intent_id: sha256_hex(b"m6-post-verification-retraction-intent"),
            intent_bytes,
            inclusion_deadline: refresh_now
                + config.status_feed_service_bond.inclusion_sla_secs,
        }),
    )?;
    let verified =
        chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_proof(
            &verifier, &live_view,
        )?;
    let error = chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_admission(
        &verifier, &live_view, &verified, now,
    )
    .err()
    .ok_or("retraction after record verification was accepted")?;
    assert!(error.detail().contains("pending"), "unexpected rejection: {error}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_status_admission_rejects_clock_rollback() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: true,
        publish_status_proof: false,
        ..LaneOptions::standard()
    })
    .await?;
    let config = market_config();
    let status_store = lane.authority.finding_status_store();
    let publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_store.clone(),
            config.status_feed_operator.clone(),
            config.status_feed_service_bond.clone(),
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let now = unix_timestamp_now();
    let live = publisher.publish_non_inclusion(&lane.deployment.web.finding_id, &[], now)?;
    let live_b64 = STANDARD.encode(&live.proof_bytes);
    let live_view = chio_kernel::finding_purchase::FindingStatusProofContextView {
        proof_b64: &live_b64,
        expected_finding_id: &lane.deployment.web.finding_id,
        expected_feed_id: &config.status_feed_operator_ref,
    };
    let verifier = MarketFindingStatusVerifier::new_with_clock(
        config.status_feed_operator,
        config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        status_store,
        Arc::new(FixedStatusAdmissionClock(now + 1)),
    )?;
    let verified =
        chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_proof(
            &verifier, &live_view,
        )?;
    let error = chio_kernel::finding_purchase::FindingStatusProofVerifier::verify_status_admission(
        &verifier,
        &live_view,
        &verified,
        now + 2,
    )
    .err()
    .ok_or("a refreshed wall clock below the durable high-water was accepted")?;
    assert!(error.detail().contains("clock rollback"), "unexpected rejection: {error}");
    Ok(())
}

/// Settling a delivered purchase signs the authoritative record, retains
/// the seller exposure, admits the payout destination behind the community
/// fund, and closes the pending-purchase slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_settles_into_a_signed_record() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: true,
        ..LaneOptions::standard()
    })
    .await?;
    let config = market_config();
    let status_store = lane.authority.finding_status_store();
    let publisher =
        crate::trust_control::finding_status_publisher::FindingStatusEpochPublisher::new(
            status_store,
            config.status_feed_operator,
            config.status_feed_service_bond,
            keypair(36),
            config.status_max_epoch_age_secs,
        )?;
    let now = unix_timestamp_now();
    let live = publisher.publish_non_inclusion(&lane.deployment.web.finding_id, &[], now)?;
    let live_b64 = STANDARD.encode(&live.proof_bytes);
    let response = lane.reveal_with_status(
        &lane.purchase,
        &live_b64,
        "wedge-settle-1",
        "nonce-settle-1",
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let finalized_at = unix_timestamp_now();

    let purchase_store = lane.authority.finding_purchase_store();
    purchase_store.register_community_fund_destination(
        &lane.deployment.web.allocation_id,
        COMMUNITY_FUND_DESTINATION,
        finalized_at,
    )?;
    let record = lane.coordinator.finalize_delivery(
        &lane.purchase.handshake.reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        finalized_at,
    )?;
    verify_signed_purchase_record(&record, &keypair(16).public_key())?;
    assert_eq!(
        record.body.purchase_key,
        derive_purchase_key(
            &lane.purchase.accepted_bid_envelope_sha256,
            &derive_payment_operation_id(&lane.purchase.handshake.reservation_id),
        )
    );
    assert_eq!(
        record.body.accepted_bid_envelope_sha256,
        lane.purchase.accepted_bid_envelope_sha256
    );
    assert_eq!(record.body.buyer, lane.buyer.public_key());
    assert_eq!(record.body.accepted_price, usd(PRICE_UNITS));
    assert_eq!(record.body.realized_spend, usd(PRICE_UNITS));
    assert_eq!(record.body.delivery_receipt_id, response.receipt.id);
    let refund_destination = BUYER_PAYOUT.to_owned();
    assert_eq!(record.body.payout_destination, refund_destination);

    let reservation = purchase_store
        .get_reservation(&lane.purchase.handshake.reservation_id)?
        .ok_or_else(|| missing("settled reservation"))?;
    assert_eq!(reservation.state, FindingPurchaseReservationState::Consumed);
    assert_eq!(record.body.recorded_at, response.receipt.timestamp);
    assert!(record.body.recorded_at >= reservation.created_at);
    assert!(
        lane.deployment
            .web
            .admission
            .body
            .purchase_authority
            .valid_from
            <= record.body.recorded_at
    );
    assert!(
        record.body.recorded_at
            < lane
                .deployment
                .web
                .admission
                .body
                .purchase_authority
                .valid_until
    );
    let slot = purchase_store
        .get_slot(&lane.purchase.handshake.reservation_id)?
        .ok_or_else(|| missing("settled slot"))?;
    assert_eq!(slot.state, FindingPurchaseSlotState::ClosedRecord);
    let encumbrance = purchase_store
        .get_encumbrance(&lane.purchase.handshake.reservation_id)?
        .ok_or_else(|| missing("retained encumbrance"))?;
    assert_eq!(encumbrance.state, FindingPurchaseEncumbranceState::Retained);
    assert_eq!(
        encumbrance.retention_expires_at,
        Some(record.body.recorded_at + LIABILITY_RETENTION_SECS)
    );
    assert_eq!(
        purchase_store.list_payout_destinations(&lane.deployment.web.allocation_id)?,
        vec![
            (0_u8, COMMUNITY_FUND_DESTINATION.to_string()),
            (1_u8, refund_destination),
        ]
    );
    assert!(purchase_store
        .get_purchase_record(&record.body.purchase_key)?
        .is_some());

    Ok(())
}
