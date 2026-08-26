use super::*;

use chio_store_sqlite::{
    SqliteFindingOperatorBundleStore, SqliteFindingOperatorPaymentAdapter,
    SqliteFindingPayloadStore, TenantId, TenantKey,
};

use crate::trust_control::finding_challenge_coordinator::FindingFilingResolver;
use crate::trust_control::finding_operator_bundle::{
    FindingOperatorBundle, FINDING_OPERATOR_BUNDLE_SCHEMA,
};
use crate::trust_control::finding_operator_filing_resolver::{
    finding_operator_bundle_artifact_indexes, FindingOperatorFilingResolver,
};
use crate::trust_control::finding_operator_purchase::{
    FindingOperatorBuyerCredential, FindingOperatorPurchaseExecutor, FindingOperatorPurchaseKeys,
    FindingOperatorPurchaseStorage,
};

const OPERATOR_PAYLOAD_KEY_BYTES: [u8; 32] = [73; 32];

#[test]
fn operator_filing_resolver_retains_pre_rotation_authority_policies() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let bundle = production_operator_bundle(&deployment.web);
    let original = market_config();
    bundle.verify_at(&original, unix_timestamp_now())?;
    let bundle_json = bundle.to_canonical_json()?;
    let indexes = finding_operator_bundle_artifact_indexes(&bundle, Some(&original))
        .map_err(std::io::Error::other)?;
    let store = SqliteFindingOperatorBundleStore::open(
        deployment
            .database
            .with_file_name("operator-historical-filing-policies.db"),
    )?;
    store.put_with_artifact_indexes(&deployment.web.finding_id, &bundle_json, &indexes)?;

    let mut rotated = original.clone();
    rotated.venue = authority_pin(80, "rotated-venue");
    rotated.governance_root = authority_pin(81, "rotated-governance");
    rotated.validate()?;
    let resolver = FindingOperatorFilingResolver::new(store, rotated.clone())
        .map_err(std::io::Error::other)?;
    let admission_digest = signed_envelope_sha256(&bundle.admission)?;
    let profile_digest = signed_envelope_sha256(&bundle.verifier_profile)?;

    assert_ne!(rotated.venue, original.venue);
    assert_ne!(rotated.governance_root, original.governance_root);
    assert_eq!(
        resolver
            .venue_policy_for_admission(&admission_digest)
            .map_err(std::io::Error::other)?,
        Some(original.venue)
    );
    assert_eq!(
        resolver
            .governance_policy_for_profile(&profile_digest)
            .map_err(std::io::Error::other)?,
        Some(original.governance_root)
    );

    let legacy_store = SqliteFindingOperatorBundleStore::open(
        deployment
            .database
            .with_file_name("operator-legacy-filing-policies.db"),
    )?;
    let legacy_indexes =
        finding_operator_bundle_artifact_indexes(&bundle, None).map_err(std::io::Error::other)?;
    legacy_store.put_with_artifact_indexes(
        &deployment.web.finding_id,
        &bundle_json,
        &legacy_indexes,
    )?;
    let legacy =
        FindingOperatorFilingResolver::new(legacy_store, rotated).map_err(std::io::Error::other)?;
    assert_eq!(
        legacy
            .venue_policy_for_admission(&admission_digest)
            .map_err(std::io::Error::other)?,
        None
    );
    assert_eq!(
        legacy
            .governance_policy_for_profile(&profile_digest)
            .map_err(std::io::Error::other)?,
        None
    );
    Ok(())
}

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
async fn cognition_market_terminal_capacity_is_reserved_before_payment() -> TestResult {
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
    let operator_db = deployment.database.with_file_name("operator-capacity.db");
    state.finding_purchase_executor = Some(Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?));
    let capacity_store = SqliteFindingOperatorBundleStore::open(&operator_db)?;
    for index in 0..16 {
        capacity_store.reserve_terminal_capacity(
            &format!("{index:064x}"),
            "capacity-fixture",
            &"f".repeat(64),
        )?;
    }

    let (status, body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(&body)?["code"], "purchase_executor_unavailable");
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
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .capture_count()
            .map_err(std::io::Error::other)?,
        0
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cognition_market_pre_reservation_crash_releases_terminal_capacity_on_expiry() -> TestResult
{
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
        .with_file_name("operator-pre-reservation-crash.db");
    let started_at = unix_timestamp_now();
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.set_test_now(started_at);
    interrupted.stop_after_terminal_capacity_once();
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
    assert!(authority
        .finding_purchase_store()
        .resolve_public_purchase_reservation(&public_request)?
        .is_none());
    let conn = rusqlite::Connection::open(&operator_db)?;
    let capacity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(capacity_count, 1);
    drop(conn);

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
    let (status, replay_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(replay_body, rejected_body);
    let conn = rusqlite::Connection::open(&operator_db)?;
    let capacity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(capacity_count, 0);
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
async fn cognition_market_pre_reservation_crash_releases_capacity_on_bundle_expiry() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;

    let payer = keypair(31).public_key().to_hex();
    let request = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 50,
        "USD".to_owned(),
        Some(payer),
        Some(900),
    )?;
    let request_body = canonical_json_bytes(&request)?;
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let operator_db = deployment
        .database
        .with_file_name("operator-pre-reservation-bundle-expiry.db");
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.set_test_now(unix_timestamp_now());
    interrupted.stop_after_terminal_capacity_once();
    state.finding_purchase_executor = Some(interrupted);

    let (status, pending_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(&pending_body)?["code"], "purchase_pending");
    let conn = rusqlite::Connection::open(&operator_db)?;
    let capacity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(capacity_count, 1);
    drop(conn);

    let resumed = Arc::new(production_purchase_executor(
        &deployment,
        authority,
        operator_db.clone(),
    )?);
    resumed.set_test_now(ADMISSION_EXPIRES_AT);
    state.finding_purchase_executor = Some(resumed);
    let (status, rejected_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(&rejected_body)?["code"], "purchase_rejected");
    let conn = rusqlite::Connection::open(&operator_db)?;
    let capacity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(capacity_count, 0);
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
async fn cognition_market_reclaims_abandoned_capacity_before_a_new_purchase() -> TestResult {
    let deployment = provision(RevealCase::honest())?;
    let authority = deployment.open()?;
    let mut state = market_state(authority.clone(), market_config());
    deployment.seed_and_activate(&state).await?;

    let payer = keypair(31).public_key().to_hex();
    let path = format!("/v1/findings/{}/purchase", deployment.web.finding_id);
    let operator_db = deployment
        .database
        .with_file_name("operator-abandoned-terminal-capacity.db");
    let started_at = unix_timestamp_now();
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.set_test_now(started_at);
    state.finding_purchase_executor = Some(interrupted.clone());

    for index in 0..16 {
        let request = FindingPurchaseRequest::new(
            deployment.web.finding_id.clone(),
            PRICE_UNITS + 50 + index,
            "USD".to_owned(),
            Some(payer.clone()),
            Some(1),
        )?;
        interrupted.stop_after_terminal_capacity_once();
        let (status, body) =
            send(&state, buyer_post(&path, canonical_json_bytes(&request)?)?).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json_body(&body)?["code"], "purchase_pending");
    }
    let conn = rusqlite::Connection::open(&operator_db)?;
    let capacity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(capacity_count, 16);
    drop(conn);

    let resumed = Arc::new(production_purchase_executor(
        &deployment,
        authority,
        operator_db.clone(),
    )?);
    resumed.set_test_now(started_at.saturating_add(1));
    resumed.stop_after_terminal_capacity_once();
    state.finding_purchase_executor = Some(resumed);
    let next = FindingPurchaseRequest::new(
        deployment.web.finding_id.clone(),
        PRICE_UNITS + 100,
        "USD".to_owned(),
        Some(payer),
        Some(900),
    )?;
    let (status, body) = send(&state, buyer_post(&path, canonical_json_bytes(&next)?)?).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(&body)?["code"], "purchase_pending");
    let conn = rusqlite::Connection::open(&operator_db)?;
    let capacity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(capacity_count, 1);
    let retained_request: String = conn.query_row(
        "SELECT request_id FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retained_request, next.request_id);
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
async fn cognition_market_predispatch_release_is_a_stable_rejection() -> TestResult {
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
        .with_file_name("operator-predispatch-release.db");
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.fail_predispatch_once();
    state.finding_purchase_executor = Some(interrupted);

    let (status, rejected_body) = send(&state, buyer_post(&path, request_body.clone())?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_body(&rejected_body)?["code"], "purchase_rejected");
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
        .ok_or_else(|| missing("released purchase reservation missing"))?;
    assert_eq!(reservation.state, FindingPurchaseReservationState::Released);

    let capacity_store = SqliteFindingOperatorBundleStore::open(&operator_db)?;
    for index in 0..16 {
        capacity_store.reserve_terminal_capacity(
            &format!("{index:064x}"),
            "capacity-fixture",
            &"f".repeat(64),
        )?;
    }

    state.finding_purchase_executor = Some(Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?));
    let (status, replay_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(replay_body, rejected_body);
    let conn = rusqlite::Connection::open(&operator_db)?;
    let capacity_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM chio_finding_operator_terminal_capacity",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(capacity_count, 16);
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
async fn cognition_market_expired_captured_restart_refunds_before_rejection() -> TestResult {
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
        .with_file_name("operator-expired-captured.db");
    let started_at = unix_timestamp_now();
    let interrupted = Arc::new(production_purchase_executor(
        &deployment,
        authority.clone(),
        operator_db.clone(),
    )?);
    interrupted.set_test_now(started_at);
    interrupted.stop_after_kernel_response_once();
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
        .ok_or_else(|| missing("captured purchase lost its reservation"))?;
    assert_eq!(
        reservation.state,
        FindingPurchaseReservationState::SlotReserved
    );
    let payment =
        SqliteFindingOperatorPaymentAdapter::open(&operator_db).map_err(std::io::Error::other)?;
    assert_eq!(payment.capture_count().map_err(std::io::Error::other)?, 1);
    assert_eq!(payment.refund_count().map_err(std::io::Error::other)?, 0);

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
            .ok_or_else(|| missing("refunded reservation disappeared"))?
            .state,
        FindingPurchaseReservationState::Expired
    );
    let payment =
        SqliteFindingOperatorPaymentAdapter::open(&operator_db).map_err(std::io::Error::other)?;
    assert_eq!(payment.capture_count().map_err(std::io::Error::other)?, 1);
    assert_eq!(payment.refund_count().map_err(std::io::Error::other)?, 1);

    let (status, replay_body) = send(&state, buyer_post(&path, request_body)?).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(replay_body, rejected_body);
    assert_eq!(
        SqliteFindingOperatorPaymentAdapter::open(&operator_db)
            .map_err(std::io::Error::other)?
            .refund_count()
            .map_err(std::io::Error::other)?,
        1
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
