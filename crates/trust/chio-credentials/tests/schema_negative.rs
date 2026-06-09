#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_credentials::{
    build_agent_passport, create_passport_presentation_challenge,
    create_signed_passport_verifier_policy, issue_reputation_credential,
    respond_to_passport_presentation_challenge, verify_agent_passport,
    verify_passport_presentation_challenge, verify_passport_presentation_response,
    verify_signed_passport_verifier_policy, AgentPassport, AttestationWindow,
    ChioCredentialEvidence, CredentialError, PassportPresentationChallenge,
    PassportPresentationOptions, PassportPresentationResponse, PassportVerifierPolicy,
    SignedPassportVerifierPolicy,
};
use chio_did::DidChio;
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};

const ISSUED_AT: u64 = 1_710_000_000;
const VALID_UNTIL: u64 = 1_710_086_400;
const VERIFY_NOW: u64 = 1_710_000_100;

trait TestResultExt<T, E> {
    fn test_ok(self, context: &str) -> T;
    fn test_err(self, context: &str) -> E;
}

impl<T, E> TestResultExt<T, E> for Result<T, E>
where
    T: std::fmt::Debug,
    E: std::fmt::Display,
{
    fn test_ok(self, context: &str) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn test_err(self, context: &str) -> E {
        match self {
            Ok(value) => panic!("{context}: unexpected Ok({value:?})"),
            Err(error) => error,
        }
    }
}

fn did_from_key(keypair: &Keypair) -> String {
    DidChio::from_public_key(keypair.public_key())
        .test_ok("derive did")
        .to_string()
}

fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: ISSUED_AT,
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
            last_seen: Some(ISSUED_AT),
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
            until: ISSUED_AT,
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

fn sample_passport() -> (Keypair, AgentPassport) {
    let issuer = Keypair::from_seed(&[11_u8; 32]);
    let holder = Keypair::from_seed(&[17_u8; 32]);
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&holder.public_key().to_hex()),
        sample_evidence(),
        ISSUED_AT,
        VALID_UNTIL,
    )
    .test_ok("issue reputation credential");
    let passport = build_agent_passport(&did_from_key(&holder), vec![credential])
        .test_ok("build agent passport");
    (holder, passport)
}

fn insert_unknown_field(document: &mut serde_json::Value, field: &str) {
    match document {
        serde_json::Value::Object(object) => {
            object.insert(field.to_string(), serde_json::json!(true));
        }
        other => panic!("expected JSON object, got {other:?}"),
    }
}

fn assert_unknown_field_error(error: serde_json::Error, document_name: &str) {
    let message = error.to_string();
    assert!(
        message.contains("unknown field"),
        "{document_name} accepted unknown field with error {message:?}"
    );
}

#[test]
fn unsupported_passport_schema_variants_fail_closed_before_signature_checks() {
    let (_holder, passport) = sample_passport();
    let bad_schemas = [
        "",
        "chio.agent-passport",
        "chio.agent-passport.v0",
        "chio.agent-passport.v9",
        "chio.agent-passport.v1 ",
        " chio.agent-passport.v1",
        "CHIO.AGENT-PASSPORT.V1",
        "https://chio.world/schemas/agent-passport.v1",
    ];

    for schema in bad_schemas {
        let mut tampered = passport.clone();
        tampered.schema = schema.to_string();
        let error = verify_agent_passport(&tampered, VERIFY_NOW)
            .test_err("unsupported passport schema must reject");
        assert!(
            matches!(error, CredentialError::InvalidPassportSchema),
            "schema {schema:?} returned {error:?}"
        );
    }
}

#[test]
fn unsupported_signed_verifier_policy_schema_variants_fail_closed() {
    let signer = Keypair::from_seed(&[23_u8; 32]);
    let document = create_signed_passport_verifier_policy(
        &signer,
        "rp-default",
        "https://verifier.example.com",
        ISSUED_AT,
        VALID_UNTIL,
        PassportVerifierPolicy::default(),
    )
    .test_ok("create signed policy");

    for schema in [
        "",
        "chio.passport-verifier-policy",
        "chio.passport-verifier-policy.v9",
    ] {
        let mut tampered = document.clone();
        tampered.body.schema = schema.to_string();
        let error = verify_signed_passport_verifier_policy(&tampered)
            .test_err("unsupported signed policy schema must reject");
        assert!(
            matches!(error, CredentialError::InvalidSignedVerifierPolicySchema),
            "schema {schema:?} returned {error:?}"
        );
    }
}

#[test]
fn unsupported_challenge_and_response_schema_variants_fail_closed() {
    let (holder, passport) = sample_passport();
    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        ISSUED_AT,
        VALID_UNTIL,
        PassportPresentationOptions::default(),
        None,
    )
    .test_ok("create challenge");

    for schema in [
        "",
        "chio.agent-passport-presentation-challenge",
        "chio.agent-passport-presentation-challenge.v9",
    ] {
        let mut tampered = challenge.clone();
        tampered.schema = schema.to_string();
        let error = verify_passport_presentation_challenge(&tampered, VERIFY_NOW)
            .test_err("unsupported challenge schema must reject");
        assert!(
            matches!(error, CredentialError::InvalidChallengeSchema),
            "schema {schema:?} returned {error:?}"
        );
    }

    let response =
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, VERIFY_NOW)
            .test_ok("respond to challenge");
    for schema in [
        "",
        "chio.agent-passport-presentation-response",
        "chio.agent-passport-presentation-response.v9",
    ] {
        let mut tampered = response.clone();
        tampered.schema = schema.to_string();
        let error = verify_passport_presentation_response(&tampered, Some(&challenge), VERIFY_NOW)
            .test_err("unsupported presentation schema must reject");
        assert!(
            matches!(error, CredentialError::InvalidPresentationSchema),
            "schema {schema:?} returned {error:?}"
        );
    }
}

#[test]
fn native_wire_documents_reject_unknown_fields_before_verification() {
    let (holder, passport) = sample_passport();
    let mut passport_json = serde_json::to_value(&passport).test_ok("serialize passport");
    insert_unknown_field(&mut passport_json, "shadowTrustTier");
    let error = serde_json::from_value::<AgentPassport>(passport_json)
        .test_err("passport unknown field must reject");
    assert_unknown_field_error(error, "passport");

    let policy_signer = Keypair::from_seed(&[23_u8; 32]);
    let signed_policy = create_signed_passport_verifier_policy(
        &policy_signer,
        "rp-default",
        "https://verifier.example.com",
        ISSUED_AT,
        VALID_UNTIL,
        PassportVerifierPolicy::default(),
    )
    .test_ok("create signed policy");
    let mut signed_policy_json =
        serde_json::to_value(&signed_policy).test_ok("serialize signed policy");
    insert_unknown_field(&mut signed_policy_json, "ambientOverride");
    let error = serde_json::from_value::<SignedPassportVerifierPolicy>(signed_policy_json)
        .test_err("signed policy unknown field must reject");
    assert_unknown_field_error(error, "signed policy");

    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        ISSUED_AT,
        VALID_UNTIL,
        PassportPresentationOptions::default(),
        None,
    )
    .test_ok("create challenge");
    let mut challenge_json = serde_json::to_value(&challenge).test_ok("serialize challenge");
    insert_unknown_field(&mut challenge_json, "relaxedNonce");
    let error = serde_json::from_value::<PassportPresentationChallenge>(challenge_json)
        .test_err("challenge unknown field must reject");
    assert_unknown_field_error(error, "challenge");

    let response =
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, VERIFY_NOW)
            .test_ok("respond to challenge");
    let mut response_json = serde_json::to_value(&response).test_ok("serialize response");
    insert_unknown_field(&mut response_json, "holderOverride");
    let error = serde_json::from_value::<PassportPresentationResponse>(response_json)
        .test_err("response unknown field must reject");
    assert_unknown_field_error(error, "response");
}
