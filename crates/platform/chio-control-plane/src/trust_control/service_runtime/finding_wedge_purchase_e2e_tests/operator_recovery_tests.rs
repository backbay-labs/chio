use super::*;

use chio_store_sqlite::{
    SqliteFindingOperatorBundleStore, SqliteFindingOperatorPaymentAdapter,
    SqliteFindingPayloadStore, TenantId, TenantKey,
};

use crate::trust_control::finding_operator_bundle::{
    FindingOperatorBundle, FINDING_OPERATOR_BUNDLE_SCHEMA,
};
use crate::trust_control::finding_operator_purchase::{
    FindingOperatorBuyerCredential, FindingOperatorPurchaseExecutor, FindingOperatorPurchaseKeys,
    FindingOperatorPurchaseStorage,
};

const OPERATOR_PAYLOAD_KEY_BYTES: [u8; 32] = [73; 32];

fn production_operator_bundle(web: &MarketWeb) -> FindingOperatorBundle {
    let mut listing = web.listing_entry();
    listing.freshness.generated_at = ISSUED_AT;
    listing.freshness.age_secs = 0;
    FindingOperatorBundle {
        schema: FINDING_OPERATOR_BUNDLE_SCHEMA.to_owned(),
        finding: web.finding.clone(),
        listing,
        admission: web.admission.clone(),
        market_terms: web.terms.clone(),
        seller_authorization: web.authorization.clone(),
        verifier_profile: web.profile.clone(),
        bond_backing: web.backing.clone(),
        verifier_report: web.report.clone(),
        fee_schedule: web.schedule.clone(),
    }
}

fn production_purchase_executor(
    deployment: &Deployment,
    authority: Arc<SqliteAuthorityStore>,
    operator_db_path: PathBuf,
) -> Result<FindingOperatorPurchaseExecutor, AnyError> {
    let config = market_config();
    let bundle = production_operator_bundle(&deployment.web);
    bundle.verify_at(&config, unix_timestamp_now())?;
    let bundle_json = bundle.to_canonical_json()?;
    SqliteFindingOperatorBundleStore::open(&operator_db_path)?
        .put(&deployment.web.finding_id, &bundle_json)?;
    SqliteFindingPayloadStore::open(&operator_db_path)?.put(
        &TenantId::new("cognition-market-pilot"),
        &TenantKey::from_bytes(OPERATOR_PAYLOAD_KEY_BYTES),
        &deployment.web.finding_id,
        deployment.web.case.sealed_media_type,
        &deployment.web.finding.payload_sha256,
        deployment.web.case.sealed_payload,
    )?;
    let buyer = FindingOperatorBuyerCredential::new(
        "buyer-agent-1".to_owned(),
        BUYER_TOKEN.to_owned(),
        keypair(31),
        BUYER_PAYOUT.to_owned(),
    )
    .map_err(std::io::Error::other)?;
    FindingOperatorPurchaseExecutor::new(
        FindingOperatorPurchaseStorage {
            authority,
            operator_db_path,
            receipt_db_path: deployment.receipt_db.clone(),
            payload_tenant_id: TenantId::new("cognition-market-pilot"),
            payload_key: TenantKey::from_bytes(OPERATOR_PAYLOAD_KEY_BYTES),
        },
        config,
        Arc::new(TestTerminalAuthorityStatusResolver::live()),
        FindingOperatorPurchaseKeys {
            listing: keypair(24),
            purchase: keypair(16),
            failed_delivery: keypair(17),
            status_operator: keypair(36),
            kernel: keypair(40),
            sellers: vec![deployment.web.operator.clone()],
        },
        vec![buyer],
        SERVICE_TOKEN,
    )
    .map_err(|error| std::io::Error::other(error).into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_production_operator_purchase_survives_cache_loss() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;

    let buyer = keypair(31);
    let payer = buyer.public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 50,
        "USD".to_owned(),
        Some(payer),
        Some(900),
    )?;
    let request_body = canonical_json_bytes(&request)?;
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let operator_a_db = deployment.database.with_file_name("operator-a.db");
    state.finding_purchase_executor = Some(Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_a_db.clone(),
    )?));

    let (status, body) = send(&state, authed_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(&body)?["code"],
        serde_json::json!("purchase_unauthorized")
    );

    let (status, first_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&first_body)
    );
    let first: FindingPurchaseResult = serde_json::from_slice(&first_body)?;
    assert_eq!(first.verdict, FindingPurchaseVerdict::Allow);
    assert_eq!(
        first.settlement,
        FindingPurchaseSettlementTerminal::Captured
    );
    assert_eq!(
        first.output,
        Some(FindingPurchasedOutput {
            media_type: REVEAL_MEDIA_TYPE.to_owned(),
            payload_b64: STANDARD.encode(SEALED_PAYLOAD),
        })
    );
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_a_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        1
    );

    // Normal process restart reopens the same terminal cache and returns the
    // canonical response without another hold or capture.
    state.finding_purchase_executor = Some(Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_a_db.clone(),
    )?));
    let (status, cached_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cached_body, first_body);
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_a_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        1
    );

    // A replacement operator database deliberately has no route terminal or
    // payment row. The request binding resolves the existing reservation
    // before rebuilding a timestamped bid, and the executor reconstructs the
    // exact response from the authority store, receipt log, and sealed payload.
    let operator_b_db = deployment.database.with_file_name("operator-b.db");
    state.finding_purchase_executor = Some(Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_b_db.clone(),
    )?));
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_b_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        0
    );
    let (status, recovered_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(recovered_body, first_body);
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_b_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        0
    );
    assert_eq!(
        authority
            .finding_purchase_store()
            .get_reservation(&first.reservation_id)?
            .ok_or_else(|| missing("production operator reservation missing"))?
            .state,
        FindingPurchaseReservationState::Consumed
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_production_operator_resumes_after_reserved_restart() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;

    let buyer = keypair(31);
    let payer = buyer.public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 50,
        "USD".to_owned(),
        Some(payer.clone()),
        Some(900),
    )?;
    let request_body = canonical_json_bytes(&request)?;
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let operator_db = deployment.database.with_file_name("operator-recovery.db");
    let interrupted =
        production_purchase_executor(&deployment, authority.clone(), operator_db.clone())?;
    interrupted.stop_after_reservation_once();
    state.finding_purchase_executor = Some(Arc::new(interrupted));

    let (status, pending_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        String::from_utf8_lossy(&pending_body)
    );
    assert_eq!(json_body(&pending_body)?["code"], "purchase_pending");
    let public_request = FindingPublicPurchaseRequestBinding {
        request_id: &request.request_id,
        finding_id: &request.finding_id,
        requested_payer: request.payer.as_deref(),
        resolved_payer: &payer,
        payer_hex: &payer,
        max_price_units: request.max_price.units,
        currency: &request.max_price.currency,
        deadline_secs: request.deadline_secs,
    };
    let reservation = authority
        .finding_purchase_store()
        .resolve_public_purchase_reservation(&public_request)?
        .ok_or_else(|| missing("interrupted purchase lost its reservation"))?;
    assert_eq!(reservation.state, FindingPurchaseReservationState::Open);
    let job_store = SqliteFindingOperatorBundleStore::open(&operator_db)?;
    assert_eq!(job_store.purchase_job_count()?, 1);
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        0
    );

    state.finding_purchase_executor = Some(Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?));
    let (status, recovered_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&recovered_body)
    );
    let recovered: FindingPurchaseResult = serde_json::from_slice(&recovered_body)?;
    assert_eq!(recovered.verdict, FindingPurchaseVerdict::Allow);
    assert_eq!(recovered.reservation_id, reservation.reservation_id);
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        1
    );

    let (status, replay_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay_body, recovered_body);
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_expired_reserved_restart_is_stably_rejected() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;

    let buyer = keypair(31);
    let payer = buyer.public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 50,
        "USD".to_owned(),
        Some(payer.clone()),
        Some(60),
    )?;
    let request_body = canonical_json_bytes(&request)?;
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let operator_db = deployment
        .database
        .with_file_name("operator-expired-reserved.db");
    let started_at = unix_timestamp_now();
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.set_test_now(started_at);
    interrupted.stop_after_reservation_once();
    state.finding_purchase_executor = Some(interrupted);

    let (status, pending_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(&pending_body)?["code"], "purchase_pending");
    let public_request = FindingPublicPurchaseRequestBinding {
        request_id: &request.request_id,
        finding_id: &request.finding_id,
        requested_payer: request.payer.as_deref(),
        resolved_payer: &payer,
        payer_hex: &payer,
        max_price_units: request.max_price.units,
        currency: &request.max_price.currency,
        deadline_secs: request.deadline_secs,
    };
    let reservation = authority
        .finding_purchase_store()
        .resolve_public_purchase_reservation(&public_request)?
        .ok_or_else(|| missing("interrupted purchase lost its reservation"))?;
    assert_eq!(reservation.state, FindingPurchaseReservationState::Open);

    let resumed = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    resumed.set_test_now(started_at.saturating_add(60));
    state.finding_purchase_executor = Some(resumed);
    let (status, rejected_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(&rejected_body)?["code"], "purchase_rejected");
    assert_eq!(
        authority
            .finding_purchase_store()
            .get_reservation(&reservation.reservation_id)?
            .ok_or_else(|| missing("expired reservation disappeared"))?
            .state,
        FindingPurchaseReservationState::Expired
    );

    let (status, replay_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(replay_body, rejected_body);
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        0
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_prepared_job_revalidates_before_first_reservation() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;

    let buyer = keypair(31);
    let payer = buyer.public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 50,
        "USD".to_owned(),
        Some(payer.clone()),
        Some(900),
    )?;
    let request_body = canonical_json_bytes(&request)?;
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let operator_db = deployment
        .database
        .with_file_name("operator-prepared-only.db");
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.stop_after_purchase_job_once();
    state.finding_purchase_executor = Some(interrupted.clone());

    let (status, pending_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(&pending_body)?["code"], "purchase_pending");
    let public_request = FindingPublicPurchaseRequestBinding {
        request_id: &request.request_id,
        finding_id: &request.finding_id,
        requested_payer: request.payer.as_deref(),
        resolved_payer: &payer,
        payer_hex: &payer,
        max_price_units: request.max_price.units,
        currency: &request.max_price.currency,
        deadline_secs: request.deadline_secs,
    };
    assert!(authority
        .finding_purchase_store()
        .resolve_public_purchase_reservation(&public_request)?
        .is_none());
    assert_eq!(
        SqliteFindingOperatorBundleStore::open(&operator_db)?.purchase_job_count()?,
        1
    );

    interrupted.set_test_now(ADMISSION_EXPIRES_AT);
    let (status, rejected_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(&rejected_body)?["code"], "purchase_rejected");
    assert!(authority
        .finding_purchase_store()
        .resolve_public_purchase_reservation(&public_request)?
        .is_none());
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        0
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_rejects_expired_prepared_ask_before_reservation() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;

    let buyer = keypair(31);
    let payer = buyer.public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 50,
        "USD".to_owned(),
        Some(payer.clone()),
        Some(60),
    )?;
    let request_body = canonical_json_bytes(&request)?;
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let operator_db = deployment
        .database
        .with_file_name("operator-expired-prepared-ask.db");
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.set_test_now(ISSUED_AT.saturating_add(10_000));
    interrupted.stop_after_purchase_job_once();
    state.finding_purchase_executor = Some(interrupted.clone());

    let (status, pending_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(&pending_body)?["code"], "purchase_pending");
    let public_request = FindingPublicPurchaseRequestBinding {
        request_id: &request.request_id,
        finding_id: &request.finding_id,
        requested_payer: request.payer.as_deref(),
        resolved_payer: &payer,
        payer_hex: &payer,
        max_price_units: request.max_price.units,
        currency: &request.max_price.currency,
        deadline_secs: request.deadline_secs,
    };
    assert!(authority
        .finding_purchase_store()
        .resolve_public_purchase_reservation(&public_request)?
        .is_none());

    interrupted.set_test_now(ISSUED_AT.saturating_add(10_061));
    let (status, rejected_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(&rejected_body)?["code"], "purchase_rejected");
    assert!(authority
        .finding_purchase_store()
        .resolve_public_purchase_reservation(&public_request)?
        .is_none());
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        0
    );
    Ok(())
}
