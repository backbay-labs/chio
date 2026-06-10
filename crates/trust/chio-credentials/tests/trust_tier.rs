#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Trust-tier synthesis tests plus passport extension coverage.

use chio_core::Keypair;
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, synthesize_trust_tier, AgentPassport,
    AttestationWindow, ChioCredentialEvidence, TrustTier, TRUST_TIER_ATTESTED_MIN,
    TRUST_TIER_PREMIER_MIN, TRUST_TIER_VERIFIED_MIN,
};
use chio_did::DidChio;
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};

fn did_from_public_key(public_key: chio_core::PublicKey) -> DidChio {
    DidChio::from_public_key(public_key).expect("ed25519 key")
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

fn sample_passport(subject_seed: u8, issuer_seed: u8) -> AgentPassport {
    let subject = Keypair::from_seed(&[subject_seed; 32]);
    let issuer = Keypair::from_seed(&[issuer_seed; 32]);
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&subject.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .expect("credential");
    let subject_did = did_from_public_key(subject.public_key());
    build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport")
}

// ---------- synthesis table tests ----------

#[test]
fn synthesis_below_attested_threshold_is_unverified() {
    assert_eq!(synthesize_trust_tier(0, false), TrustTier::Unverified);
    assert_eq!(synthesize_trust_tier(299, false), TrustTier::Unverified);
    assert_eq!(synthesize_trust_tier(299, true), TrustTier::Unverified);
}

#[test]
fn synthesis_attested_band_maps_to_attested() {
    assert_eq!(
        synthesize_trust_tier(TRUST_TIER_ATTESTED_MIN, false),
        TrustTier::Attested
    );
    assert_eq!(synthesize_trust_tier(500, false), TrustTier::Attested);
    assert_eq!(
        synthesize_trust_tier(TRUST_TIER_VERIFIED_MIN - 1, false),
        TrustTier::Attested
    );
    // Anomaly does not change things inside the attested band.
    assert_eq!(synthesize_trust_tier(500, true), TrustTier::Attested);
}

#[test]
fn synthesis_verified_band_maps_to_verified() {
    assert_eq!(
        synthesize_trust_tier(TRUST_TIER_VERIFIED_MIN, false),
        TrustTier::Verified
    );
    assert_eq!(synthesize_trust_tier(800, false), TrustTier::Verified);
    assert_eq!(
        synthesize_trust_tier(TRUST_TIER_PREMIER_MIN - 1, false),
        TrustTier::Verified
    );
    // Anomaly keeps us at Verified inside this band as well.
    assert_eq!(synthesize_trust_tier(800, true), TrustTier::Verified);
}

#[test]
fn synthesis_premier_requires_clear_anomaly() {
    // Top band, clear behavior -> Premier.
    assert_eq!(synthesize_trust_tier(950, false), TrustTier::Premier);
    assert_eq!(synthesize_trust_tier(1000, false), TrustTier::Premier);
    assert_eq!(
        synthesize_trust_tier(TRUST_TIER_PREMIER_MIN, false),
        TrustTier::Premier
    );
    // Top band with an active anomaly degrades to Verified.
    assert_eq!(synthesize_trust_tier(950, true), TrustTier::Verified);
    assert_eq!(synthesize_trust_tier(1000, true), TrustTier::Verified);
}

#[test]
fn synthesis_is_deterministic() {
    // Same inputs produce the same output every call.
    for _ in 0..16 {
        assert_eq!(synthesize_trust_tier(650, false), TrustTier::Attested);
        assert_eq!(synthesize_trust_tier(650, true), TrustTier::Attested);
        assert_eq!(synthesize_trust_tier(920, false), TrustTier::Premier);
        assert_eq!(synthesize_trust_tier(920, true), TrustTier::Verified);
    }
}

#[test]
fn tier_labels_match_serde_wire_form() {
    assert_eq!(TrustTier::Unverified.label(), "unverified");
    assert_eq!(TrustTier::Attested.label(), "attested");
    assert_eq!(TrustTier::Verified.label(), "verified");
    assert_eq!(TrustTier::Premier.label(), "premier");
    for tier in [
        TrustTier::Unverified,
        TrustTier::Attested,
        TrustTier::Verified,
        TrustTier::Premier,
    ] {
        let json = serde_json::to_string(&tier).expect("serialize tier");
        assert_eq!(json, format!("\"{}\"", tier.label()));
    }
}

// ---------- passport extension tests ----------

#[test]
fn passport_default_has_no_trust_tier_and_omits_field_on_wire() {
    let passport = sample_passport(1, 2);
    assert!(passport.trust_tier.is_none());
    let json = serde_json::to_string(&passport).expect("passport json");
    assert!(
        !json.contains("trustTier"),
        "passport without trust_tier must omit the field on the wire: {json}"
    );
}

#[test]
fn passport_with_trust_tier_roundtrips_through_serde() {
    let mut passport = sample_passport(3, 4);
    passport.trust_tier = Some(TrustTier::Premier);
    let json = serde_json::to_string(&passport).expect("passport json");
    assert!(json.contains("\"trustTier\":\"premier\""));
    let decoded: AgentPassport = serde_json::from_str(&json).expect("deserialize passport");
    assert_eq!(decoded, passport);
    assert_eq!(decoded.trust_tier, Some(TrustTier::Premier));
}

#[test]
fn passport_without_trust_tier_on_wire_still_deserializes() {
    let passport = sample_passport(5, 6);
    let mut json_value: serde_json::Value =
        serde_json::to_value(&passport).expect("serialize passport");
    // Simulate a pre-20.1 passport: strip the field entirely.
    if let Some(object) = json_value.as_object_mut() {
        object.remove("trustTier");
    }
    let decoded: AgentPassport =
        serde_json::from_value(json_value).expect("deserialize legacy passport");
    assert!(decoded.trust_tier.is_none());
    assert_eq!(decoded.subject, passport.subject);
}

#[test]
fn all_four_tier_values_roundtrip_inside_a_passport() {
    for tier in [
        TrustTier::Unverified,
        TrustTier::Attested,
        TrustTier::Verified,
        TrustTier::Premier,
    ] {
        let mut passport = sample_passport(7, 8);
        passport.trust_tier = Some(tier);
        let json = serde_json::to_string(&passport).expect("passport json");
        let decoded: AgentPassport = serde_json::from_str(&json).expect("deserialize passport");
        assert_eq!(decoded.trust_tier, Some(tier));
    }
}
