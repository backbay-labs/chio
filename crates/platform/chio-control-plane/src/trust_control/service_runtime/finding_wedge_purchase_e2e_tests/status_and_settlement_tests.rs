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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_purchase_without_status_verifier_denies_before_effects() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let denied = lane.reveal("m6-missing-status-verifier", "m6-missing-status-nonce")?;
    assert_denied_with(&denied, "configured finding status verifier");
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finding_status_retraction() -> TestResult {
    let lane = open_lane(LaneOptions {
        install_status_verifier: true,
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
    buyer_memory_write(&lane.deployment, &delivered.receipt, &lane.buyer)?;

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
    let status_gate_live = status_gate_publisher.publish_non_inclusion(
        &status_lane.deployment.web.finding_id,
        &[],
        now,
    )?;
    let status_gate_live_b64 = STANDARD.encode(&status_gate_live.proof_bytes);

    let intent_id = sha256_hex(b"m6-voluntary-retraction-intent");
    let intent_bytes = canonical_json_bytes(&serde_json::json!({
        "finding_id": lane.deployment.web.finding_id,
        "reason": "seller_voluntary_retraction",
        "schema": "chio.finding.voluntary-retraction.v1",
    }))?;
    let intent = chio_store_sqlite::FindingRetractionIntentInput {
        intent_id: &intent_id,
        feed_id: &config.status_feed_operator_ref,
        operator_id: &config.status_feed_operator.authority.authority_id,
        finding_id: &lane.deployment.web.finding_id,
        source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
        intent_bytes: &intent_bytes,
        issued_at: now,
        inclusion_deadline: now + config.status_feed_service_bond.inclusion_sla_secs,
        created_at: now,
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
        .publish_non_inclusion(&lane.deployment.web.finding_id, &[], now)
        .is_err());

    let hook_store = status_gate_store.clone();
    let hook_intent_id = intent_id.clone();
    let hook_feed_id = config.status_feed_operator_ref.clone();
    let hook_operator_id = config.status_feed_operator.authority.authority_id.clone();
    let hook_finding_id = lane.deployment.web.finding_id.clone();
    let hook_intent_bytes = intent_bytes.clone();
    let inclusion_deadline = intent.inclusion_deadline;
    status_lane
        .kernel
        .set_payment_adapter(Box::new(ReversibleHoldAdapter {
            calls: status_lane.calls.clone(),
            authorize_hook: Some(Arc::new(move || {
                hook_store
                    .issue_retraction_intent(&chio_store_sqlite::FindingRetractionIntentInput {
                        intent_id: &hook_intent_id,
                        feed_id: &hook_feed_id,
                        operator_id: &hook_operator_id,
                        finding_id: &hook_finding_id,
                        source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
                        intent_bytes: &hook_intent_bytes,
                        issued_at: now,
                        inclusion_deadline,
                        created_at: now,
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
    assert_eq!(status_lane.calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(status_lane.calls.releases.load(Ordering::SeqCst), 1);
    assert_eq!(status_lane.invocations.load(Ordering::SeqCst), 0);

    let included = status_gate_publisher.publish_retraction(&intent_id, &[], now)?;
    let included_b64 = STANDARD.encode(&included.proof_bytes);
    let duplicate = status_gate_publisher.publish_retraction(&intent_id, &[], now)?;
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
    status_gate_store.issue_retraction_intent(
        &chio_store_sqlite::FindingRetractionIntentInput {
            intent_id: &second_intent_id,
            feed_id: &config.status_feed_operator_ref,
            operator_id: &config.status_feed_operator.authority.authority_id,
            finding_id: &second_finding_id,
            source: chio_store_sqlite::FindingRetractionIntentSource::Voluntary,
            intent_bytes: &second_intent_bytes,
            issued_at: now,
            inclusion_deadline: now + config.status_feed_service_bond.inclusion_sla_secs,
            created_at: now,
        },
    )?;
    let second_included =
        status_gate_publisher.publish_retraction(&second_intent_id, &[], now + 1)?;
    let refresh_candidates = status_gate_store.list_publication_candidates(
        &config.status_feed_operator_ref,
        now + 1,
        200,
    )?;
    assert!(refresh_candidates
        .iter()
        .any(|candidate| candidate.intent_id == intent_id));
    assert!(status_gate_store
        .get_latest_proof(&config.status_feed_operator_ref, &lane.deployment.web.finding_id)?
        .is_none());
    let refreshed_included =
        status_gate_publisher.publish_retraction(&intent_id, &[], now + 1)?;
    assert_eq!(refreshed_included.map_epoch, second_included.map_epoch);
    assert_eq!(
        refreshed_included.kind,
        chio_store_sqlite::FindingStatusProofKind::Inclusion
    );
    assert!(!status_gate_store
        .list_publication_candidates(&config.status_feed_operator_ref, now + 1, 200)?
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
    let rotated = rotated_publisher.publish_non_inclusion(
        &sha256_hex(b"m6-live-after-operator-rotation"),
        &[],
        now + 2,
    )?;
    assert_eq!(rotated.map_epoch, prior_epoch + 1);
    assert_eq!(
        status_gate_store
            .get_current_epoch(&config.status_feed_operator_ref)?
            .operator_key_epoch,
        rotated_operator.authority.key_epoch
    );

    publisher.publish_retraction(&intent_id, &[], now)?;
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

    let purchase_store = lane.authority.finding_purchase_store();
    purchase_store.register_community_fund_destination(
        &lane.deployment.web.allocation_id,
        COMMUNITY_FUND_DESTINATION,
        now,
    )?;
    let record = lane.coordinator.finalize_delivery(
        &lane.purchase.handshake.reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
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
