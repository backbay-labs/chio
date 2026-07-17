use super::super::super::*;
use super::super::budget::build_remote_budget_store;
use super::super::client::{build_client, should_retry_status};
use super::super::errors::{
    into_budget_store_error, into_receipt_store_error, into_revocation_store_error,
};
use super::super::issuance::ensure_signed_by_trusted_authority;
use super::support::{assert_json_post, StaticResponseServer};
use chio_test_support::prelude::*;

#[test]
fn budget_wrappers_use_split_budget_routes() {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 3);
    let client = build_client(&server.url, "secret").test_expect("build client");

    let _ = client.try_charge_cost("cap-budget", 2, Some(9), 120, Some(150), Some(900));
    let _ = client.reverse_charge_cost("cap-budget", 2, 120);
    let _ = client.reconcile_budget_spend("cap-budget", 2, 120, 75);

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_json_post(
        &requests[0],
        BUDGET_AUTHORIZE_EXPOSURE_PATH,
        &[
            "\"exposureUnits\":120",
            "\"maxExposurePerInvocation\":150",
            "\"maxTotalExposureUnits\":900",
        ],
    );
    assert_json_post(
        &requests[1],
        BUDGET_RELEASE_EXPOSURE_PATH,
        &["\"exposureUnits\":120"],
    );
    assert_json_post(
        &requests[2],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"authorizedExposureUnits\":120",
            "\"realizedSpendUnits\":75",
            "\"reductionUnits\":45",
        ],
    );
}

#[test]
fn budget_wrappers_include_budget_event_identity_when_provided() {
    let server = StaticResponseServer::spawn(200, "{}", "application/json", 3);
    let client = build_client(&server.url, "secret").test_expect("build client");

    let _ = client.try_charge_cost_with_ids(
        "cap-budget",
        2,
        Some(9),
        120,
        Some(150),
        Some(900),
        Some("hold-budget"),
        Some("hold-budget:authorize"),
    );
    let _ = client.reverse_charge_cost_with_ids(
        "cap-budget",
        2,
        120,
        Some("hold-budget"),
        Some("hold-budget:reverse"),
    );
    let _ = client.reconcile_budget_spend_with_ids(
        "cap-budget",
        2,
        120,
        75,
        Some("hold-budget"),
        Some("hold-budget:reconcile"),
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_json_post(
        &requests[0],
        BUDGET_AUTHORIZE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:authorize\"",
        ],
    );
    assert_json_post(
        &requests[1],
        BUDGET_RELEASE_EXPOSURE_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:reverse\"",
        ],
    );
    assert_json_post(
        &requests[2],
        BUDGET_RECONCILE_SPEND_PATH,
        &[
            "\"holdId\":\"hold-budget\"",
            "\"eventId\":\"hold-budget:reconcile\"",
        ],
    );
}

#[test]
fn budget_usage_view_round_trips_split_and_aggregate_fields() {
    let usage: BudgetUsageView = serde_json::from_value(serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 3,
        "invocationCount": 4,
        "totalExposureCharged": 75,
        "totalRealizedSpend": 60,
        "updatedAt": 1234,
        "seq": 9
    }))
    .test_expect("parse split budget usage view");

    assert_eq!(usage.capability_id, "cap-budget");
    assert_eq!(usage.grant_index, 3);
    assert_eq!(usage.invocation_count, 4);
    assert_eq!(usage.total_cost_exposed, 75);
    assert_eq!(usage.total_cost_realized_spend, 60);
    assert_eq!(usage.updated_at, 1234);
    assert_eq!(usage.seq, Some(9));

    let encoded = serde_json::to_value(&usage).test_expect("serialize budget usage view");
    assert_eq!(encoded["totalExposureCharged"], 75);
    assert_eq!(encoded["totalRealizedSpend"], 60);
    assert!(encoded.get("totalCostCharged").is_none());
}

#[test]
fn remote_budget_store_preserves_authority_term_and_commit_metadata() {
    let body = serde_json::json!({
        "capabilityId": "cap-budget",
        "grantIndex": 2,
        "allowed": true,
        "invocationCount": 5,
        "totalExposureCharged": 120,
        "totalRealizedSpend": 75,
        "budgetAuthority": {
            "authorityId": "http://leader-a",
            "leaderUrl": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "http://leader-a#term-7",
            "leaseEpoch": 7,
            "leaseExpiresAt": 5000,
            "leaseTtlMs": 750,
            "guaranteeLevel": "ha_quorum_commit",
            "budgetCommitIndex": 41
        },
        "budgetCommit": {
            "budgetSeq": 41,
            "commitIndex": 41,
            "quorumCommitted": true,
            "quorumSize": 2,
            "committedNodes": 2,
            "witnessUrls": ["http://leader-a", "http://peer-b"],
            "authorityId": "http://leader-a",
            "budgetTerm": 7,
            "leaseId": "http://leader-a#term-7",
            "leaseEpoch": 7
        }
    })
    .to_string();
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store =
        build_remote_budget_store(&server.url, "secret").test_expect("build remote budget store");

    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-budget".to_string(),
            grant_index: 2,
            max_invocations: Some(9),
            requested_exposure_units: 120,
            max_cost_per_invocation: Some(150),
            max_total_cost_units: Some(900),
            hold_id: Some("hold-budget".to_string()),
            event_id: Some("hold-budget:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })
        .test_expect("authorize remote budget hold");

    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        panic!("expected remote authorize to succeed");
    };
    let authority = authorized
        .metadata
        .authority
        .test_expect("budget authority metadata");
    assert_eq!(authority.authority_id, "http://leader-a");
    assert_eq!(authority.lease_id, "http://leader-a#term-7");
    assert_eq!(authority.lease_epoch, 7);
    assert_eq!(authorized.metadata.budget_commit_index, Some(41));
    assert_eq!(
        authorized.metadata.guarantee_level,
        BudgetGuaranteeLevel::HaLinearizable
    );
    assert_eq!(
        authorized.metadata.event_id.as_deref(),
        Some("hold-budget:authorize")
    );

    let usage = store
        .get_usage("cap-budget", 2)
        .test_expect("get cached usage")
        .test_expect("cached usage record");
    assert_eq!(usage.seq, 41);
    assert_eq!(usage.invocation_count, 5);
    assert_eq!(usage.total_cost_exposed, 120);
    assert_eq!(usage.total_cost_realized_spend, 75);
}

#[test]
fn authority_key_cache_from_status_validates_and_deduplicates_current_key() {
    let current = Keypair::generate().public_key().to_hex();
    let trusted_only = Keypair::generate().public_key().to_hex();

    let cache = AuthorityKeyCache::from_status(&TrustAuthorityStatus {
        configured: true,
        backend: Some("sqlite".to_string()),
        public_key: Some(current.clone()),
        generation: Some(7),
        rotated_at: Some(11),
        applies_to_future_sessions_only: false,
        trusted_public_keys: vec![trusted_only.clone()],
    })
    .test_expect("cache from valid status");

    assert_eq!(
        cache.current.as_ref().test_expect("current key").to_hex(),
        current
    );
    assert_eq!(cache.trusted.len(), 2);
    assert!(cache
        .trusted
        .iter()
        .any(|public_key| public_key.to_hex() == current));
    assert!(cache
        .trusted
        .iter()
        .any(|public_key| public_key.to_hex() == trusted_only));

    let missing_current = match AuthorityKeyCache::from_status(&TrustAuthorityStatus {
        configured: true,
        backend: None,
        public_key: None,
        generation: None,
        rotated_at: None,
        applies_to_future_sessions_only: false,
        trusted_public_keys: Vec::new(),
    }) {
        Ok(_) => panic!("missing current key should fail"),
        Err(error) => error,
    };
    assert!(missing_current
        .to_string()
        .contains("no current authority public key"));

    let unconfigured = match AuthorityKeyCache::from_status(&TrustAuthorityStatus {
        configured: false,
        backend: None,
        public_key: Some(current),
        generation: None,
        rotated_at: None,
        applies_to_future_sessions_only: false,
        trusted_public_keys: Vec::new(),
    }) {
        Ok(_) => panic!("unconfigured authority should fail"),
        Err(error) => error,
    };
    assert!(unconfigured
        .to_string()
        .contains("does not have an authority configured"));
}

#[test]
fn trusted_authority_signer_check_accepts_rotated_keys() {
    let current = Keypair::generate().public_key();
    let previous = Keypair::generate().public_key();
    let outsider = Keypair::generate().public_key();
    let trusted = vec![previous.clone(), current];

    ensure_signed_by_trusted_authority("trust activation", &previous, &trusted)
        .test_expect("previous authority key should remain trusted");
    let error = ensure_signed_by_trusted_authority("trust activation", &outsider, &trusted)
        .test_expect_err("outsider signer should fail closed");
    assert!(error
        .to_string()
        .contains("does not match a trusted trust-control authority signer"));
}

#[test]
fn retry_statuses_and_error_adapters_match_expected_behavior() {
    assert!(should_retry_status(500));
    assert!(should_retry_status(502));
    assert!(should_retry_status(503));
    assert!(should_retry_status(504));
    assert!(!should_retry_status(400));
    assert!(!should_retry_status(401));

    let message = "backend unavailable".to_string();
    let receipt_error = into_receipt_store_error(CliError::cli_other_error(message.clone()));
    let revocation_error = into_revocation_store_error(CliError::cli_other_error(message.clone()));
    let budget_error = into_budget_store_error(CliError::cli_other_error(message.clone()));

    assert!(receipt_error.to_string().contains(&message));
    assert!(revocation_error.to_string().contains(&message));
    assert!(budget_error.to_string().contains(&message));
}
