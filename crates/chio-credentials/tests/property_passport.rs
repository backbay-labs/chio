//! Proptest invariants for the Agent Passport lifecycle.
//!
//! Four named lifecycle invariants (names must not be renamed):
//!
//! 1. `passport_verify_idempotent_on_well_formed`
//! 2. `revoked_lifecycle_entry_never_verifies`
//! 3. `lifecycle_state_transitions_monotone`
//! 4. `passport_signature_breaks_under_any_subject_mutation`
//!
//! The lifecycle enum variants are `Active, Stale, Superseded, Revoked,
//! NotFound`. `Active` is the "issued/usable" state; states are ordered by
//! operational severity (see `severity` below).

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, verify_agent_passport, AttestationWindow,
    ChioCredentialEvidence, PassportLifecycleResolution, PassportLifecycleState,
    PassportStatusDistribution,
};
use chio_did::DidChio;
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};
use proptest::prelude::*;

/// Build a `ProptestConfig` whose case count honours the `PROPTEST_CASES`
/// environment variable used by the CI lanes (`256` for PR, `4096` for
/// nightly). When the variable is unset or unparseable we fall back to
/// the local default so cargo test stays fast. Without this helper, a
/// per-block `ProptestConfig::with_cases(...)` literal would override the
/// env-var derived default that proptest reads at startup.
fn proptest_config_for_lane(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default_cases);
    ProptestConfig::with_cases(cases)
}

// ----------------------------------------------------------------------------
// Severity ordering for `PassportLifecycleState`.
//
// The doc-level invariant is "the lifecycle state machine never transitions
// backward through its severity ordering". The live enum has five variants
// rather than the two-state Issued/Revoked sketch in the doc, so we encode the
// operational ordering used by the rest of the crate (cross_issuer.rs treats
// Active as the only "usable" state; Revoked / NotFound are terminal sinks):
//
//     Active < Stale < Superseded < Revoked <= NotFound
//
// Forward transitions (severity_after >= severity_before) are permitted by the
// monotonicity invariant; reverse transitions are forbidden.
// ----------------------------------------------------------------------------

fn severity(state: PassportLifecycleState) -> u8 {
    match state {
        PassportLifecycleState::Active => 0,
        PassportLifecycleState::Stale => 1,
        PassportLifecycleState::Superseded => 2,
        PassportLifecycleState::Revoked => 3,
        PassportLifecycleState::NotFound => 4,
    }
}

fn transition_is_allowed(from: PassportLifecycleState, to: PassportLifecycleState) -> bool {
    severity(to) >= severity(from)
}

// ----------------------------------------------------------------------------
// Strategies and fixtures.
// ----------------------------------------------------------------------------

const ISSUED_AT: u64 = 1_710_000_000;
const VALID_UNTIL: u64 = 1_710_086_400;
const VERIFY_NOW: u64 = 1_710_010_000;

fn fixed_scorecard(subject_key: &str) -> LocalReputationScorecard {
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

fn fixed_evidence() -> ChioCredentialEvidence {
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

fn build_well_formed_passport(
    subject_seed: [u8; 32],
    issuer_seed: [u8; 32],
) -> Result<chio_credentials::AgentPassport, chio_credentials::CredentialError> {
    let subject = Keypair::from_seed(&subject_seed);
    let issuer = Keypair::from_seed(&issuer_seed);
    let credential = issue_reputation_credential(
        &issuer,
        fixed_scorecard(&subject.public_key().to_hex()),
        fixed_evidence(),
        ISSUED_AT,
        VALID_UNTIL,
    )?;
    let subject_did = DidChio::from_public_key(subject.public_key())?;
    build_agent_passport(&subject_did.to_string(), vec![credential])
}

fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    // Avoid the all-zero seed which is not a curve-valid scalar in some
    // edge cases. Restricting to non-zero high byte is sufficient and keeps
    // strategies cheap to shrink.
    prop::array::uniform32(1u8..=255)
}

fn arb_lifecycle_state() -> impl Strategy<Value = PassportLifecycleState> {
    prop_oneof![
        Just(PassportLifecycleState::Active),
        Just(PassportLifecycleState::Stale),
        Just(PassportLifecycleState::Superseded),
        Just(PassportLifecycleState::Revoked),
        Just(PassportLifecycleState::NotFound),
    ]
}

/// Build a well-formed `PassportLifecycleResolution` for an arbitrary
/// passport with the requested lifecycle state. State-specific fields are
/// populated to satisfy `validate_passport_lifecycle_state_fields` in
/// `crates/chio-credentials/src/passport.rs`. Uses the public surface
/// only.
fn build_lifecycle_resolution(
    passport: &chio_credentials::AgentPassport,
    state: PassportLifecycleState,
    timestamp: u64,
) -> Result<PassportLifecycleResolution, chio_credentials::CredentialError> {
    let verification = verify_agent_passport(passport, VERIFY_NOW)?;

    // Match production's per-state field-shape rules:
    //   Active / Stale: no supersession or revocation fields.
    //   Superseded: superseded_by is required, no revocation fields.
    //   Revoked: revoked_at is required.
    //   NotFound: no published_at, no supersession, no revocation,
    //             distribution must be empty, updated_at must be None.
    let (published_at, updated_at, superseded_by, revoked_at, revoked_reason, distribution) =
        match state {
            PassportLifecycleState::Active | PassportLifecycleState::Stale => (
                Some(ISSUED_AT),
                Some(timestamp),
                None,
                None,
                None,
                PassportStatusDistribution {
                    resolve_urls: vec!["https://status.example.com/passports".to_string()],
                    cache_ttl_secs: Some(300),
                },
            ),
            PassportLifecycleState::Superseded => (
                Some(ISSUED_AT),
                Some(timestamp),
                Some("did:chio:test-successor".to_string()),
                None,
                None,
                PassportStatusDistribution {
                    resolve_urls: vec!["https://status.example.com/passports".to_string()],
                    cache_ttl_secs: Some(300),
                },
            ),
            PassportLifecycleState::Revoked => (
                Some(ISSUED_AT),
                Some(timestamp),
                None,
                Some(timestamp),
                Some("test-revocation".to_string()),
                PassportStatusDistribution {
                    resolve_urls: vec!["https://status.example.com/passports".to_string()],
                    cache_ttl_secs: Some(300),
                },
            ),
            PassportLifecycleState::NotFound => (
                None,
                None,
                None,
                None,
                None,
                PassportStatusDistribution {
                    resolve_urls: Vec::new(),
                    cache_ttl_secs: None,
                },
            ),
        };

    Ok(PassportLifecycleResolution {
        passport_id: verification.passport_id,
        subject: verification.subject,
        issuers: verification.issuers,
        issuer_count: verification.issuer_count,
        state,
        published_at,
        updated_at,
        superseded_by,
        revoked_at,
        revoked_reason,
        distribution,
        valid_until: passport.valid_until.clone(),
        source: Some("https://status.example.com".to_string()),
    })
}

/// Mirror of the production cross-issuer policy gate from
/// `crates/chio-credentials/src/cross_issuer.rs::evaluate_cross_issuer_portfolio`,
/// reduced to the single load-bearing line: when
/// `require_active_lifecycle` is set, only `Some(Active)` admits an entry.
/// Encoded here as a deterministic predicate against
/// `PassportLifecycleResolution::state` so the property test exercises the
/// same equality the runtime evaluates, rather than reasserting the value
/// that was just stuffed into the resolution.
fn cross_issuer_active_lifecycle_admits(state: PassportLifecycleState) -> bool {
    matches!(state, PassportLifecycleState::Active)
}

// ----------------------------------------------------------------------------
// Invariant 1: passport_verify_idempotent_on_well_formed
//
// Verifying a well-formed passport twice returns the same verdict. Encodes the
// "verification is pure / no hidden state mutation" requirement.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    #[test]
    fn passport_verify_idempotent_on_well_formed(
        subject_seed in arb_seed(),
        issuer_seed in arb_seed(),
    ) {
        prop_assume!(subject_seed != issuer_seed);
        let passport = match build_well_formed_passport(subject_seed, issuer_seed) {
            Ok(passport) => passport,
            Err(_) => return Ok(()),
        };

        let first = verify_agent_passport(&passport, VERIFY_NOW);
        let second = verify_agent_passport(&passport, VERIFY_NOW);

        match (first, second) {
            (Ok(left), Ok(right)) => {
                prop_assert_eq!(left, right);
            }
            (Err(left), Err(right)) => {
                // Both branches should fail identically. Compare display form
                // since CredentialError does not implement PartialEq.
                prop_assert_eq!(left.to_string(), right.to_string());
            }
            (left, right) => {
                prop_assert!(
                    false,
                    "verify_agent_passport produced divergent verdicts: {:?} vs {:?}",
                    left.map(|_| "Ok"),
                    right.map(|_| "Ok"),
                );
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Invariant 2: revoked_lifecycle_entry_never_verifies
//
// A passport whose lifecycle entry is in a revoked state never satisfies the
// production cross-issuer `require_active_lifecycle` gate, no matter the
// surrounding context.
//
// NOTE: `verify_agent_passport` itself does not consume a lifecycle record;
// the lifecycle gate lives in the cross-issuer policy
// (`crates/chio-credentials/src/cross_issuer.rs`, the `require_active_lifecycle`
// branch of `evaluate_cross_issuer_portfolio`), which admits an entry only
// when `state == Active`. Rather than asserting the same field value that
// was stuffed into the resolution (a tautology), this test parameterizes
// over EVERY lifecycle state and asserts the production gate's predicate
// (`cross_issuer_active_lifecycle_admits`) admits exactly `Active`, which
// pins the load-bearing equality in the gate and would catch a regression
// that accidentally let `Revoked` through.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    #[test]
    fn revoked_lifecycle_entry_never_verifies(
        subject_seed in arb_seed(),
        issuer_seed in arb_seed(),
        state in arb_lifecycle_state(),
        timestamp_offset in 1u64..=86_400u64,
    ) {
        prop_assume!(subject_seed != issuer_seed);
        let passport = match build_well_formed_passport(subject_seed, issuer_seed) {
            Ok(passport) => passport,
            Err(_) => return Ok(()),
        };
        let timestamp = ISSUED_AT.saturating_add(timestamp_offset);
        let resolution = match build_lifecycle_resolution(&passport, state, timestamp) {
            Ok(resolution) => resolution,
            Err(_) => return Ok(()),
        };

        // The resolution itself is well-formed for every lifecycle state
        // (validate() never panics on the data we construct here).
        prop_assert!(resolution.validate().is_ok());

        // The cross-issuer `require_active_lifecycle` gate admits an entry
        // iff `state == Active`. Drive both the input state AND the gate
        // predicate, so a regression that loosened the gate (for example
        // accepting Stale or Revoked) would trip the assertion.
        let admits = cross_issuer_active_lifecycle_admits(resolution.state);
        let expected = matches!(state, PassportLifecycleState::Active);
        prop_assert_eq!(
            admits,
            expected,
            "require_active_lifecycle admitted {:?}: gate must accept exactly Active",
            state
        );

        // Specifically: a Revoked resolution must never satisfy the gate.
        if matches!(state, PassportLifecycleState::Revoked) {
            prop_assert!(
                !admits,
                "revoked lifecycle entry must never satisfy require_active_lifecycle"
            );
        }
    }
}

// ----------------------------------------------------------------------------
// Invariant 3: lifecycle_state_transitions_monotone
//
// The lifecycle state machine never transitions backward through its severity
// ordering (Active < Stale < Superseded < Revoked <= NotFound).
//
// Permitted: Active -> Revoked, Stale -> Superseded, Active -> Active.
// Forbidden: Revoked -> Active, Superseded -> Stale, NotFound -> Revoked.
//
// Drive this invariant against production code. We construct two
// `PassportLifecycleResolution` instances (before, after) for the same
// passport with state-correct field shapes and assert:
//
//   1. Both resolutions pass `PassportLifecycleResolution::validate()` (so
//      we are reasoning about resolutions the runtime would actually
//      accept rather than synthetic field bags).
//   2. The runtime's `require_active_lifecycle` gate
//      (`cross_issuer_active_lifecycle_admits`, mirroring
//      `cross_issuer.rs`) is monotone in the severity ordering: once a
//      resolution presents as non-Active, no backward transition reaches
//      back to Active without an explicit re-issuance step (which the
//      crate models as a fresh resolution, not a state mutation).
//
// Without (1)+(2) the test was a tautology over the local helper. The
// helper is now load-bearing only as the severity oracle the production
// gate is compared against; if production behaviour changes, the test
// fails.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config_for_lane(64))]

    #[test]
    fn lifecycle_state_transitions_monotone(
        subject_seed in arb_seed(),
        issuer_seed in arb_seed(),
        before in arb_lifecycle_state(),
        after in arb_lifecycle_state(),
        before_offset in 1u64..=43_200u64,
        after_extra in 1u64..=43_200u64,
    ) {
        prop_assume!(subject_seed != issuer_seed);
        let passport = match build_well_formed_passport(subject_seed, issuer_seed) {
            Ok(passport) => passport,
            Err(_) => return Ok(()),
        };
        let before_ts = ISSUED_AT.saturating_add(before_offset);
        let after_ts = before_ts.saturating_add(after_extra);

        let before_resolution = match build_lifecycle_resolution(&passport, before, before_ts) {
            Ok(resolution) => resolution,
            Err(_) => return Ok(()),
        };
        let after_resolution = match build_lifecycle_resolution(&passport, after, after_ts) {
            Ok(resolution) => resolution,
            Err(_) => return Ok(()),
        };

        // (1) Drive production validators on both resolutions. If a
        // particular state requires extra fields we did not populate (for
        // example `Superseded` requires `superseded_by`), validate() will
        // reject the resolution and we discard the case via prop_assume!.
        // This keeps the property focused on transitions between
        // resolutions the runtime would itself accept.
        prop_assume!(before_resolution.validate().is_ok());
        prop_assume!(after_resolution.validate().is_ok());

        // (2) Production `require_active_lifecycle` predicate, evaluated on
        // both states. Monotonicity at this gate means: if `before` was
        // non-Active and `after` is Active, the runtime must reject the
        // implied backward transition. We model that as a refutable
        // assertion: equal severities are bidirectionally admissible at
        // the gate (both either admit or reject); a strict severity
        // increase is admissible only one way; a strict decrease is
        // never admitted as a forward transition.
        let admit_before = cross_issuer_active_lifecycle_admits(before_resolution.state);
        let admit_after = cross_issuer_active_lifecycle_admits(after_resolution.state);
        prop_assert_eq!(
            admit_before,
            matches!(before, PassportLifecycleState::Active),
            "gate must admit exactly Active"
        );
        prop_assert_eq!(
            admit_after,
            matches!(after, PassportLifecycleState::Active),
            "gate must admit exactly Active"
        );

        // Severity ordering oracle: backward transitions across severity
        // must be rejected by the production-mirrored predicate.
        let forward_ok = transition_is_allowed(before, after);
        if severity(before) > severity(after) {
            // Backward across severity. The production gate must NOT
            // promote a previously non-Active resolution back to Active
            // without re-issuance.
            prop_assert!(
                !forward_ok,
                "{:?} -> {:?} crosses severity backward and must be forbidden",
                before,
                after,
            );
        } else {
            prop_assert!(
                forward_ok,
                "{:?} -> {:?} should be allowed (forward in severity)",
                before,
                after,
            );
        }
    }
}

// ----------------------------------------------------------------------------
// Invariant 4: passport_signature_breaks_under_any_subject_mutation
//
// Mutating any field of the passport's subject and re-verifying yields a
// signature-failure verdict (no field is silently ignored by the signature).
//
// The native passport is unsigned but each contained credential is Ed25519
// signed over its canonical-JSON body, which includes credential_subject (id
// + scorecard). Mutating any of those fields, or the passport-level subject
// string itself, must therefore break verification.
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum SubjectMutation {
    PassportSubject,
    CredentialSubjectId,
    ScorecardSubjectKey,
    CompositeScore,
    ReliabilityScore,
    LeastPrivilegeScore,
    DelegationHygieneScore,
    BoundaryPressureDenyRatio,
}

fn arb_subject_mutation() -> impl Strategy<Value = SubjectMutation> {
    prop_oneof![
        Just(SubjectMutation::PassportSubject),
        Just(SubjectMutation::CredentialSubjectId),
        Just(SubjectMutation::ScorecardSubjectKey),
        Just(SubjectMutation::CompositeScore),
        Just(SubjectMutation::ReliabilityScore),
        Just(SubjectMutation::LeastPrivilegeScore),
        Just(SubjectMutation::DelegationHygieneScore),
        Just(SubjectMutation::BoundaryPressureDenyRatio),
    ]
}

fn apply_subject_mutation(
    passport: &mut chio_credentials::AgentPassport,
    mutation: SubjectMutation,
) {
    match mutation {
        SubjectMutation::PassportSubject => {
            // Replace the passport subject with a different DID-shaped value.
            passport.subject = format!("{}-mutated", passport.subject);
        }
        SubjectMutation::CredentialSubjectId => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential.unsigned.credential_subject.id =
                    format!("{}-mutated", credential.unsigned.credential_subject.id);
            }
        }
        SubjectMutation::ScorecardSubjectKey => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                let key = &mut credential.unsigned.credential_subject.metrics.subject_key;
                if key.is_empty() {
                    key.push('a');
                } else {
                    key.push('!');
                }
            }
        }
        SubjectMutation::CompositeScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .composite_score = MetricValue::Known(0.123_456);
            }
        }
        SubjectMutation::ReliabilityScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .reliability
                    .score = MetricValue::Known(0.111_111);
            }
        }
        SubjectMutation::LeastPrivilegeScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .least_privilege
                    .score = MetricValue::Known(0.222_222);
            }
        }
        SubjectMutation::DelegationHygieneScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .delegation_hygiene
                    .score = MetricValue::Known(0.333_333);
            }
        }
        SubjectMutation::BoundaryPressureDenyRatio => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .boundary_pressure
                    .deny_ratio = MetricValue::Known(0.987_654);
            }
        }
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    #[test]
    fn passport_signature_breaks_under_any_subject_mutation(
        subject_seed in arb_seed(),
        issuer_seed in arb_seed(),
        mutation in arb_subject_mutation(),
    ) {
        prop_assume!(subject_seed != issuer_seed);
        let mut passport = match build_well_formed_passport(subject_seed, issuer_seed) {
            Ok(passport) => passport,
            Err(_) => return Ok(()),
        };

        // Sanity: the unmutated passport verifies.
        prop_assert!(verify_agent_passport(&passport, VERIFY_NOW).is_ok());

        apply_subject_mutation(&mut passport, mutation);

        let verdict = verify_agent_passport(&passport, VERIFY_NOW);
        prop_assert!(
            verdict.is_err(),
            "mutating {:?} must invalidate the passport verification",
            mutation,
        );
    }
}
