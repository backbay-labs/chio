use chio_core::crypto::Keypair;
use chio_credentials::{
    build_agent_passport, create_passport_presentation_challenge,
    create_signed_passport_verifier_policy, ensure_signed_passport_verifier_policy_active,
    issue_chio_passport_jwt_vc_json, issue_chio_passport_sd_jwt_vc, issue_reputation_credential,
    respond_to_oid4vp_request, respond_to_passport_presentation_challenge,
    sign_oid4vp_request_object, verify_agent_passport, verify_chio_passport_jwt_vc_json,
    verify_chio_passport_sd_jwt_vc, verify_oid4vp_direct_post_response,
    verify_passport_presentation_challenge, verify_passport_presentation_response,
    verify_signed_oid4vp_request_object, verify_signed_passport_verifier_policy, AgentPassport,
    AttestationWindow, ChioCredentialEvidence, CredentialError, Oid4vpDcqlQuery,
    Oid4vpRequestObject, Oid4vpRequestedCredential, PassportPresentationOptions,
    PassportVerifierPolicy, CHIO_PASSPORT_SD_JWT_VC_FORMAT, CHIO_PASSPORT_SD_JWT_VC_TYPE,
    OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI, OID4VP_RESPONSE_MODE_DIRECT_POST_JWT,
    OID4VP_RESPONSE_TYPE_VP_TOKEN,
};
use chio_did::DidChio;
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};

use chio_test_support::ctx::{TestUnwrap, TestUnwrapErr};

fn did_from_public_key(public_key: chio_core::PublicKey) -> DidChio {
    DidChio::from_public_key(public_key).test_unwrap("ed25519 key")
}

fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: 1_710_000_000,
        boundary_pressure: BoundaryPressureMetrics {
            deny_ratio: MetricValue::Known(0.1),
            policies_observed: 1,
            receipts_observed: 3,
        },
        resource_stewardship: ResourceStewardshipMetrics {
            average_utilization: MetricValue::Known(0.6),
            fit_score: MetricValue::Known(0.9),
            capped_grants_observed: 1,
        },
        least_privilege: LeastPrivilegeMetrics {
            score: MetricValue::Known(0.8),
            capabilities_observed: 1,
        },
        history_depth: HistoryDepthMetrics {
            score: MetricValue::Known(0.7),
            receipt_count: 3,
            active_days: 3,
            first_seen: Some(1_709_900_000),
            last_seen: Some(1_710_000_000),
            span_days: 3,
            activity_ratio: MetricValue::Known(1.0),
        },
        specialization: SpecializationMetrics {
            score: MetricValue::Known(0.5),
            distinct_tools: 2,
        },
        delegation_hygiene: DelegationHygieneMetrics {
            score: MetricValue::Known(0.9),
            delegations_observed: 1,
            scope_reduction_rate: MetricValue::Known(1.0),
            ttl_reduction_rate: MetricValue::Known(1.0),
            budget_reduction_rate: MetricValue::Known(1.0),
        },
        reliability: ReliabilityMetrics {
            score: MetricValue::Known(0.95),
            completion_rate: MetricValue::Known(1.0),
            cancellation_rate: MetricValue::Known(0.0),
            incompletion_rate: MetricValue::Known(0.0),
            receipts_observed: 3,
        },
        incident_correlation: IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        },
        composite_score: MetricValue::Known(0.82),
        effective_weight_sum: 0.9,
    }
}

fn sample_evidence() -> ChioCredentialEvidence {
    ChioCredentialEvidence {
        query: AttestationWindow {
            since: Some(1_709_900_000),
            until: 1_710_000_000,
        },
        receipt_count: 3,
        receipt_ids: vec![
            "rcpt-1".to_string(),
            "rcpt-2".to_string(),
            "rcpt-3".to_string(),
        ],
        checkpoint_roots: vec!["abc123".to_string()],
        receipt_log_urls: vec!["https://trust.example.com/v1/receipts".to_string()],
        lineage_records: 1,
        uncheckpointed_receipts: 0,
        runtime_attestation: None,
    }
}

fn sample_passport(subject_seed: u8, issuer_seed: u8) -> Result<AgentPassport, CredentialError> {
    let subject = Keypair::from_seed(&[subject_seed; 32]);
    let issuer = Keypair::from_seed(&[issuer_seed; 32]);
    let subject_did = did_from_public_key(subject.public_key());
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&subject.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )?;

    build_agent_passport(&subject_did.to_string(), vec![credential])
}

#[test]
fn passport_issue_verify_and_present_round_trip() {
    let issuer = Keypair::from_seed(&[1_u8; 32]);
    let holder = Keypair::from_seed(&[7_u8; 32]);
    let holder_did = did_from_public_key(holder.public_key());
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&holder.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .test_unwrap("issue reputation credential");
    let passport = build_agent_passport(&holder_did.to_string(), vec![credential])
        .test_unwrap("build passport");

    let verification =
        verify_agent_passport(&passport, 1_710_000_100).test_unwrap("verify passport");
    assert_eq!(verification.subject, holder_did.to_string());
    assert_eq!(verification.credential_count, 1);

    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        1_710_000_110,
        1_710_000_410,
        PassportPresentationOptions::default(),
        Some(PassportVerifierPolicy {
            min_receipt_count: Some(1),
            ..PassportVerifierPolicy::default()
        }),
    )
    .test_unwrap("build challenge");
    let response =
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, 1_710_000_120)
            .test_unwrap("respond to challenge");
    let verification =
        verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
            .test_unwrap("verify presentation response");

    assert!(verification.accepted);
    assert!(verification.policy_evaluated);
    assert_eq!(verification.subject, holder_did.to_string());
    assert_eq!(verification.credential_count, 1);
}

#[test]
fn presentation_rejects_holder_mismatch() {
    let issuer = Keypair::from_seed(&[1_u8; 32]);
    let holder = Keypair::from_seed(&[7_u8; 32]);
    let wrong_holder = Keypair::from_seed(&[9_u8; 32]);
    let holder_did = did_from_public_key(holder.public_key());
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&holder.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .test_unwrap("issue credential");
    let passport = build_agent_passport(&holder_did.to_string(), vec![credential])
        .test_unwrap("build passport");
    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        1_710_000_110,
        1_710_000_410,
        PassportPresentationOptions::default(),
        None,
    )
    .test_unwrap("build challenge");

    let error = respond_to_passport_presentation_challenge(
        &wrong_holder,
        &passport,
        &challenge,
        1_710_000_120,
    )
    .test_unwrap_err("wrong holder should fail closed");

    assert!(matches!(error, CredentialError::PresentationHolderMismatch));
}

#[test]
fn portable_credentials_expire_at_exact_exp() {
    let issuer = Keypair::from_seed(&[21_u8; 32]);
    let passport = sample_passport(22, 23).test_unwrap("build passport for portable expiration");

    let sd_jwt = issue_chio_passport_sd_jwt_vc(
        &passport,
        "https://trust.example.com",
        &issuer,
        1_710_000_100,
        None,
    )
    .test_unwrap("issue portable sd-jwt");
    let sd_jwt_error =
        verify_chio_passport_sd_jwt_vc(&sd_jwt.compact, &issuer.public_key(), 1_710_086_400)
            .test_unwrap_err("portable sd-jwt should expire at exact exp");
    assert!(sd_jwt_error.to_string().contains("expired"));

    let jwt_vc = issue_chio_passport_jwt_vc_json(
        &passport,
        "https://trust.example.com",
        &issuer,
        1_710_000_100,
        None,
    )
    .test_unwrap("issue portable jwt vc");
    let jwt_vc_error =
        verify_chio_passport_jwt_vc_json(&jwt_vc.compact, &issuer.public_key(), 1_710_086_400)
            .test_unwrap_err("portable jwt vc should expire at exact exp");
    assert!(jwt_vc_error.to_string().contains("expired"));
}

#[test]
fn oid4vp_artifacts_expire_at_exact_exp() {
    let authority = Keypair::from_seed(&[31_u8; 32]);
    let issuer = Keypair::from_seed(&[32_u8; 32]);
    let holder = Keypair::from_seed(&[33_u8; 32]);
    let holder_did = did_from_public_key(holder.public_key());
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&holder.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .test_unwrap("issue reputation credential");
    let passport =
        build_agent_passport(&holder_did.to_string(), vec![credential]).test_unwrap("passport");
    let portable = issue_chio_passport_sd_jwt_vc(
        &passport,
        "https://trust.example.com",
        &issuer,
        1_710_000_100,
        None,
    )
    .test_unwrap("portable credential");
    let request = Oid4vpRequestObject {
        client_id: "https://verifier.example.com".to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri: "https://verifier.example.com/v1/public/passport/oid4vp/direct-post"
            .to_string(),
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce: "nonce-1".to_string(),
        state: "state-1".to_string(),
        iat: 1_710_000_100,
        exp: 1_710_000_400,
        jti: "oid4vp-1".to_string(),
        request_uri: "https://verifier.example.com/v1/public/passport/oid4vp/requests/oid4vp-1"
            .to_string(),
        dcql_query: Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "chio-passport".to_string(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: vec!["chio_issuer_dids".to_string()],
                issuer_allowlist: vec!["https://trust.example.com".to_string()],
            }],
        },
        identity_assertion: None,
    };

    let request_jwt =
        sign_oid4vp_request_object(&request, &authority).test_unwrap("sign request object");
    let request_error =
        verify_signed_oid4vp_request_object(&request_jwt, &authority.public_key(), request.exp)
            .test_unwrap_err("OID4VP request should expire at exact exp");
    assert!(request_error.to_string().contains("expired"));

    let mut long_lived_request = request;
    long_lived_request.exp = 1_710_001_000;
    let response_jwt = respond_to_oid4vp_request(
        &holder,
        &portable.compact,
        &long_lived_request,
        1_710_000_200,
    )
    .test_unwrap("respond to oid4vp request");
    let response_error = verify_oid4vp_direct_post_response(
        &response_jwt,
        &long_lived_request,
        &issuer.public_key(),
        1_710_000_500,
    )
    .test_unwrap_err("OID4VP response should expire at exact exp");
    assert!(response_error.to_string().contains("expired"));
}

#[test]
fn signed_verifier_policy_activation_window_is_inclusive() {
    let signer = Keypair::from_seed(&[3_u8; 32]);
    let document = create_signed_passport_verifier_policy(
        &signer,
        "rp-default",
        "https://verifier.example.com",
        1_710_000_000,
        1_710_000_300,
        PassportVerifierPolicy::default(),
    )
    .test_unwrap("sign verifier policy");

    ensure_signed_passport_verifier_policy_active(&document, 1_710_000_000)
        .test_unwrap("created_at boundary should be valid");
    ensure_signed_passport_verifier_policy_active(&document, 1_710_000_300)
        .test_unwrap("expires_at boundary should be valid");
}

#[test]
fn unknown_passport_schema_rejects_before_verify() -> Result<(), CredentialError> {
    let mut passport = sample_passport(11, 12)?;
    passport.schema = "chio.agent-passport.v99".to_string();

    assert!(matches!(
        verify_agent_passport(&passport, 1_710_000_100),
        Err(CredentialError::InvalidPassportSchema)
    ));
    Ok(())
}

#[test]
fn unknown_signed_verifier_policy_schema_rejects_before_signature() -> Result<(), CredentialError> {
    let signer = Keypair::from_seed(&[13_u8; 32]);
    let mut document = create_signed_passport_verifier_policy(
        &signer,
        "rp-default",
        "https://verifier.example.com",
        1_710_000_000,
        1_710_000_300,
        PassportVerifierPolicy::default(),
    )?;
    document.body.schema = "chio.passport-verifier-policy.v99".to_string();

    assert!(matches!(
        verify_signed_passport_verifier_policy(&document),
        Err(CredentialError::InvalidSignedVerifierPolicySchema)
    ));
    Ok(())
}

#[test]
fn unknown_presentation_challenge_schema_rejects_before_window_check() -> Result<(), CredentialError>
{
    let mut challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        1_710_000_110,
        1_710_000_410,
        PassportPresentationOptions::default(),
        None,
    )?;
    challenge.schema = "chio.agent-passport-presentation-challenge.v99".to_string();

    assert!(matches!(
        verify_passport_presentation_challenge(&challenge, 1_710_000_120),
        Err(CredentialError::InvalidChallengeSchema)
    ));
    Ok(())
}

#[test]
fn unknown_presentation_response_schema_rejects_before_signature() -> Result<(), CredentialError> {
    let holder = Keypair::from_seed(&[17_u8; 32]);
    let passport = sample_passport(17, 18)?;
    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        1_710_000_110,
        1_710_000_410,
        PassportPresentationOptions::default(),
        None,
    )?;
    let mut response =
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, 1_710_000_120)?;
    response.schema = "chio.agent-passport-presentation-response.v99".to_string();

    assert!(matches!(
        verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120),
        Err(CredentialError::InvalidPresentationSchema)
    ));
    Ok(())
}
