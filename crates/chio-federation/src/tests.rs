use crate::activation::*;
use crate::artifacts::*;
use crate::capability::scope::MonetaryAmount;
use crate::error::*;
use crate::listing::{
    GenericListingActorKind, GenericListingFreshnessState, GenericListingReplicaFreshness,
    GenericRegistryPublisher, GenericRegistryPublisherRole, GenericTrustAdmissionClass,
};
use crate::open_admission::*;
use crate::open_market::fee_schedule::OpenMarketBondClass;
use crate::qualification::*;
use crate::quorum::*;
use crate::reputation::*;
use crate::validation::*;

fn must<T, E: core::fmt::Debug>(result: std::result::Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err:?}"),
    }
}

fn must_some<T>(option: Option<T>, context: &str) -> T {
    match option {
        Some(value) => value,
        None => panic!("{context}"),
    }
}

fn hex(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

#[test]
fn hex_digest_helper_preserves_exact_uppercase_compatible_digest_contract() {
    assert!(is_hex_digest_64(&"a".repeat(64)));
    assert!(is_hex_digest_64(&"A".repeat(64)));
    assert!(!is_hex_digest_64(&"a".repeat(63)));
    assert!(!is_hex_digest_64(&format!("{}g", "a".repeat(63))));
}

#[test]
fn hex_digest_validation_rejects_padded_digest() {
    let padded = format!(" {} ", hex('a'));
    assert!(matches!(
        validate_hex_digest(&padded, "digest"),
        Err(FederationContractError::InvalidReference(_))
    ));
}

fn sample_reference(
    kind: FederationArtifactKind,
    schema: &str,
    artifact_id: &str,
    operator_id: &str,
    seed: char,
) -> FederationArtifactReference {
    FederationArtifactReference {
        kind,
        schema: schema.to_string(),
        artifact_id: artifact_id.to_string(),
        operator_id: operator_id.to_string(),
        sha256: hex(seed),
        uri: Some(format!(
            "https://{operator_id}.chio.example/artifacts/{artifact_id}"
        )),
    }
}

fn sample_activation_exchange() -> FederationActivationExchangeArtifact {
    FederationActivationExchangeArtifact {
        schema: CHIO_FEDERATION_ACTIVATION_EXCHANGE_SCHEMA.to_string(),
        exchange_id: "fex-1".to_string(),
        issued_at: 1_743_552_000,
        expires_at: 1_743_638_400,
        source_operator_id: "origin-operator".to_string(),
        target_operator_id: "consumer-operator".to_string(),
        listing_id: "listing-liability-provider-1".to_string(),
        activation_ref: sample_reference(
            FederationArtifactKind::TrustActivation,
            "chio.registry.trust-activation.v1",
            "activation-1",
            "origin-operator",
            'a',
        ),
        listing_ref: sample_reference(
            FederationArtifactKind::Listing,
            "chio.registry.listing.v1",
            "listing-liability-provider-1",
            "origin-operator",
            'b',
        ),
        governing_charter_ref: Some(sample_reference(
            FederationArtifactKind::GovernanceCharter,
            "chio.registry.governance-charter.v1",
            "charter-1",
            "origin-operator",
            'c',
        )),
        scope: FederationTrustScope {
            namespace: "registry.chio.example/liability".to_string(),
            subject_operator_id: "origin-operator".to_string(),
            allowed_actor_kinds: vec![GenericListingActorKind::LiabilityProvider],
            allowed_admission_classes: vec![
                GenericTrustAdmissionClass::Reviewable,
                GenericTrustAdmissionClass::BondBacked,
            ],
            policy_reference: Some("policy/federation/default".to_string()),
        },
        delegation_control: FederationDelegationControl {
            delegator_operator_id: "origin-operator".to_string(),
            delegate_operator_id: "consumer-operator".to_string(),
            max_hops: 2,
            attenuation_required: true,
            visibility_only_until_local_activation: true,
        },
        import_control: FederationImportControl::default(),
        note: Some(
            "Shares one reviewed trust activation without widening runtime trust.".to_string(),
        ),
    }
}

fn sample_quorum_report() -> FederationQuorumReport {
    FederationQuorumReport {
            schema: CHIO_FEDERATION_QUORUM_REPORT_SCHEMA.to_string(),
            report_id: "fqr-1".to_string(),
            generated_at: 1_743_552_060,
            namespace: "registry.chio.example/liability".to_string(),
            listing_id: "listing-liability-provider-1".to_string(),
            origin_operator_id: "origin-operator".to_string(),
            quorum_threshold: 2,
            max_replica_age_secs: 300,
            publishers: vec![
                FederationPublisherObservation {
                    publisher: GenericRegistryPublisher {
                        role: GenericRegistryPublisherRole::Origin,
                        operator_id: "origin-operator".to_string(),
                        operator_name: Some("Origin Operator".to_string()),
                        registry_url: "https://origin.chio.example/registry".to_string(),
                        upstream_registry_urls: vec![],
                    },
                    report_ref: sample_reference(
                        FederationArtifactKind::ListingReport,
                        "chio.registry.listing-report.v1",
                        "report-origin-1",
                        "origin-operator",
                        'd',
                    ),
                    observed_listing_sha256: hex('1'),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 30,
                        max_age_secs: 300,
                        valid_until: 1_743_552_360,
                        generated_at: 1_743_552_030,
                    },
                    observed_at: 1_743_552_030,
                    upstream_hop_count: 0,
                },
                FederationPublisherObservation {
                    publisher: GenericRegistryPublisher {
                        role: GenericRegistryPublisherRole::Mirror,
                        operator_id: "mirror-operator-a".to_string(),
                        operator_name: Some("Mirror Operator A".to_string()),
                        registry_url: "https://mirror-a.chio.example/registry".to_string(),
                        upstream_registry_urls: vec![
                            "https://origin.chio.example/registry".to_string(),
                        ],
                    },
                    report_ref: sample_reference(
                        FederationArtifactKind::ListingReport,
                        "chio.registry.listing-report.v1",
                        "report-mirror-a-1",
                        "mirror-operator-a",
                        'e',
                    ),
                    observed_listing_sha256: hex('1'),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 40,
                        max_age_secs: 300,
                        valid_until: 1_743_552_360,
                        generated_at: 1_743_552_020,
                    },
                    observed_at: 1_743_552_020,
                    upstream_hop_count: 1,
                },
                FederationPublisherObservation {
                    publisher: GenericRegistryPublisher {
                        role: GenericRegistryPublisherRole::Indexer,
                        operator_id: "indexer-operator-a".to_string(),
                        operator_name: Some("Indexer Operator A".to_string()),
                        registry_url: "https://indexer-a.chio.example/registry".to_string(),
                        upstream_registry_urls: vec![
                            "https://origin.chio.example/registry".to_string(),
                        ],
                    },
                    report_ref: sample_reference(
                        FederationArtifactKind::ListingReport,
                        "chio.registry.listing-report.v1",
                        "report-indexer-a-1",
                        "indexer-operator-a",
                        'f',
                    ),
                    observed_listing_sha256: hex('1'),
                    freshness: GenericListingReplicaFreshness {
                        state: GenericListingFreshnessState::Fresh,
                        age_secs: 45,
                        max_age_secs: 300,
                        valid_until: 1_743_552_360,
                        generated_at: 1_743_552_015,
                    },
                    observed_at: 1_743_552_015,
                    upstream_hop_count: 1,
                },
            ],
            conflicts: vec![],
            anti_eclipse_policy: FederationAntiEclipsePolicy::default(),
            final_state: FederationQuorumState::Converged,
            note: Some("Requires origin plus independent mirror/indexer observation before a remote listing is treated as converged."
                .to_string()),
        }
}

fn sample_open_admission_policy() -> FederatedOpenAdmissionPolicyArtifact {
    FederatedOpenAdmissionPolicyArtifact {
            schema: CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA.to_string(),
            policy_id: "foap-1".to_string(),
            issued_at: 1_743_552_120,
            namespace: "registry.chio.example/liability".to_string(),
            governing_operator_id: "origin-operator".to_string(),
            allowed_admission_classes: vec![
                GenericTrustAdmissionClass::PublicUntrusted,
                GenericTrustAdmissionClass::Reviewable,
                GenericTrustAdmissionClass::BondBacked,
            ],
            stake_requirements: vec![FederatedStakeRequirement {
                admission_class: GenericTrustAdmissionClass::BondBacked,
                required_bond_class: Some(OpenMarketBondClass::Listing),
                minimum_bond_amount: Some(MonetaryAmount {
                    units: 10_000,
                    currency: "USD".to_string(),
                }),
                slashable: true,
                governance_case_required: false,
            }],
            governing_charter_ref: sample_reference(
                FederationArtifactKind::GovernanceCharter,
                "chio.registry.governance-charter.v1",
                "charter-1",
                "origin-operator",
                '2',
            ),
            fee_schedule_ref: sample_reference(
                FederationArtifactKind::OpenMarketFeeSchedule,
                "chio.registry.market-fee-schedule.v1",
                "fee-schedule-1",
                "origin-operator",
                '3',
            ),
            explicit_local_review_required: true,
            visibility_only_without_activation: true,
            note: Some("Allows public visibility, but runtime trust still requires explicit local review or bond-backed admission."
                .to_string()),
        }
}

fn sample_reputation_clearing() -> FederatedReputationClearingArtifact {
    FederatedReputationClearingArtifact {
            schema: CHIO_FEDERATION_REPUTATION_CLEARING_SCHEMA.to_string(),
            clearing_id: "frc-1".to_string(),
            generated_at: 1_743_552_180,
            subject_key: "subject-1".to_string(),
            namespace: "registry.chio.example/liability".to_string(),
            participating_operator_ids: vec![
                "origin-operator".to_string(),
                "mirror-operator-a".to_string(),
                "indexer-operator-a".to_string(),
                "consumer-operator".to_string(),
            ],
            local_weighting_policy_ref: "policy/reputation/federated-default".to_string(),
            admission_policy_ref: "foap-1".to_string(),
            inputs: vec![
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::ReputationSummary,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableReputationSummary,
                        "chio.portable-reputation-summary.v1",
                        "summary-origin-1",
                        "origin-operator",
                        '4',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "origin-operator".to_string(),
                    issuer_independence_group_id: Some("operator-group-origin".to_string()),
                    weight_bps: 3_000,
                    blocking: false,
                    published_at: 1_743_552_000,
                    expires_at: Some(1_743_638_400),
                    note: Some("Origin-issued portable reputation summary.".to_string()),
                },
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::ReputationSummary,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableReputationSummary,
                        "chio.portable-reputation-summary.v1",
                        "summary-mirror-a-1",
                        "mirror-operator-a",
                        '5',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "mirror-operator-a".to_string(),
                    issuer_independence_group_id: Some("operator-group-mirror".to_string()),
                    weight_bps: 2_500,
                    blocking: false,
                    published_at: 1_743_552_010,
                    expires_at: Some(1_743_638_400),
                    note: Some("Mirror-issued portable reputation summary.".to_string()),
                },
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::NegativeEvent,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableNegativeEvent,
                        "chio.portable-negative-event.v1",
                        "negative-indexer-a-1",
                        "indexer-operator-a",
                        '6',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "indexer-operator-a".to_string(),
                    issuer_independence_group_id: Some("operator-group-indexer".to_string()),
                    weight_bps: 2_000,
                    blocking: true,
                    published_at: 1_743_552_020,
                    expires_at: Some(1_743_595_200),
                    note: Some("Indexers contribute corroborated negative-event evidence."
                        .to_string()),
                },
                FederatedReputationInputReference {
                    kind: FederatedReputationInputKind::NegativeEvent,
                    artifact_ref: sample_reference(
                        FederationArtifactKind::PortableNegativeEvent,
                        "chio.portable-negative-event.v1",
                        "negative-origin-1",
                        "origin-operator",
                        '7',
                    ),
                    subject_key: "subject-1".to_string(),
                    issuer_operator_id: "origin-operator".to_string(),
                    issuer_independence_group_id: Some("operator-group-origin".to_string()),
                    weight_bps: 1_500,
                    blocking: true,
                    published_at: 1_743_552_025,
                    expires_at: Some(1_743_595_200),
                    note: Some("Independent corroboration keeps a single issuer from becoming a universal oracle."
                        .to_string()),
                },
            ],
            sybil_control: FederatedSybilControl::default(),
            accepted_input_ids: vec![
                "summary-origin-1".to_string(),
                "summary-mirror-a-1".to_string(),
                "negative-indexer-a-1".to_string(),
                "negative-origin-1".to_string(),
            ],
            rejected_input_ids: vec![],
            effective_admission_class: GenericTrustAdmissionClass::Reviewable,
            continuity: Some(FederatedReputationClearingContinuity {
                continuity_id: "registry.chio.example/liability:subject-1".to_string(),
                previous_clearing_id: None,
            }),
            note: Some("Shared reputation clearing preserves local weighting and requires corroborated negative-event inputs."
                .to_string()),
        }
}

fn sample_qualification_matrix() -> FederationQualificationMatrix {
    FederationQualificationMatrix {
            schema: CHIO_FEDERATION_QUALIFICATION_MATRIX_SCHEMA.to_string(),
            profile_id: "chio.federation.profile".to_string(),
            exchange_ref: "fex-1".to_string(),
            quorum_report_ref: "fqr-1".to_string(),
            reputation_clearing_ref: "frc-1".to_string(),
            cases: vec![
                FederationQualificationCase {
                    id: "activation-exchange".to_string(),
                    name: "Federated activation exchange stays visibility-first and locally reviewable"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-01".to_string()],
                    scenario: FederationScenarioKind::ConflictingActivation,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Remote trust activation remains an explicit exchange contract and never becomes ambient runtime trust."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "quorum-conflict".to_string(),
                    name: "Quorum, freshness, and anti-eclipse posture remain machine-reviewable"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-02".to_string()],
                    scenario: FederationScenarioKind::InsufficientQuorum,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Conflicting or stale publisher state fails closed instead of silently rewriting trust."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "open-admission-boundary".to_string(),
                    name: "Open admission stays bounded by explicit stake and review policy"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-03".to_string()],
                    scenario: FederationScenarioKind::GovernanceInterop,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Visibility and participation stay distinct from runtime trust, even when bond-backed admission is allowed."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "shared-reputation-sybil".to_string(),
                    name: "Shared reputation clearing resists duplicate-issuer and oracle collapse"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-04".to_string()],
                    scenario: FederationScenarioKind::ReputationSybil,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Accepted summaries come from distinct issuers and blocking negative events require corroboration."
                        .to_string(),
                },
                FederationQualificationCase {
                    id: "adversarial-federation".to_string(),
                    name: "Hostile publisher and eclipse attempts fail closed under the federation boundary"
                        .to_string(),
                    requirement_ids: vec!["TRUSTMAX-05".to_string()],
                    scenario: FederationScenarioKind::EclipseAttempt,
                    expected_outcome: FederationQualificationOutcome::Pass,
                    observed_outcome: FederationQualificationOutcome::Pass,
                    notes: "Hostile federation inputs remain visible but do not collapse governance or admission into ambient trust."
                        .to_string(),
                },
            ],
        }
}

fn sample_conflict() -> FederationConflictEvidence {
    FederationConflictEvidence {
        divergence_key: "listing-liability-provider-1:hash-mismatch".to_string(),
        publisher_operator_ids: vec![
            "origin-operator".to_string(),
            "mirror-operator-a".to_string(),
        ],
        reason: "origin and mirror observed different listing bodies".to_string(),
    }
}

#[test]
fn activation_exchange_requires_local_policy_import() {
    let mut exchange = sample_activation_exchange();
    exchange.import_control.explicit_local_activation_required = false;
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));
}

#[test]
fn quorum_report_requires_origin_publisher() {
    let mut report = sample_quorum_report();
    report.publishers.remove(0);
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));
}

#[test]
fn open_admission_policy_requires_bond_requirement() {
    let mut policy = sample_open_admission_policy();
    policy.stake_requirements.clear();
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::InvalidAdmission(_))
    ));
}

#[test]
fn reputation_clearing_rejects_duplicate_summary_issuer() {
    let mut clearing = sample_reputation_clearing();
    clearing.inputs[1].issuer_operator_id = "origin-operator".to_string();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));
}

#[test]
fn reference_artifacts_parse_and_validate() {
    let exchange: FederationActivationExchangeArtifact = must(
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_FEDERATION_ACTIVATION_EXCHANGE_EXAMPLE.json"
        )),
        "parse activation exchange reference",
    );
    let quorum: FederationQuorumReport = must(
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_FEDERATION_QUORUM_REPORT_EXAMPLE.json"
        )),
        "parse quorum report reference",
    );
    let admission: FederatedOpenAdmissionPolicyArtifact = must(
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_FEDERATION_OPEN_ADMISSION_POLICY_EXAMPLE.json"
        )),
        "parse admission policy reference",
    );
    let clearing: FederatedReputationClearingArtifact = must(
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_FEDERATION_REPUTATION_CLEARING_EXAMPLE.json"
        )),
        "parse reputation clearing reference",
    );
    let matrix: FederationQualificationMatrix = must(
        serde_json::from_str(include_str!(
            "../../../docs/standards/CHIO_FEDERATION_QUALIFICATION_MATRIX.json"
        )),
        "parse qualification matrix reference",
    );

    must(
        validate_federation_activation_exchange(&exchange),
        "validate activation exchange reference",
    );
    must(
        validate_federation_quorum_report(&quorum),
        "validate quorum report reference",
    );
    must(
        validate_federated_open_admission_policy(&admission),
        "validate admission policy reference",
    );
    must(
        validate_federated_reputation_clearing(&clearing),
        "validate reputation clearing reference",
    );
    must(
        validate_federation_qualification_matrix(&matrix),
        "validate qualification matrix reference",
    );
}

#[test]
fn qualification_matrix_requires_requirement_coverage() {
    let mut matrix = sample_qualification_matrix();
    matrix.cases.pop();
    assert!(matches!(
        validate_federation_qualification_matrix(&matrix),
        Err(FederationContractError::InvalidQualificationCase(_))
    ));
}

#[test]
fn activation_exchange_rejects_schema_reference_and_operator_mismatches() {
    let mut exchange = sample_activation_exchange();
    exchange.schema = "chio.federation-activation-exchange.v0".to_string();
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::UnsupportedSchema(_))
    ));

    let mut exchange = sample_activation_exchange();
    exchange.target_operator_id = exchange.source_operator_id.clone();
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut exchange = sample_activation_exchange();
    exchange.expires_at = exchange.issued_at;
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut exchange = sample_activation_exchange();
    exchange.activation_ref.kind = FederationArtifactKind::Listing;
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut exchange = sample_activation_exchange();
    exchange.listing_ref.kind = FederationArtifactKind::TrustActivation;
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut exchange = sample_activation_exchange();
    must_some(
        exchange.governing_charter_ref.as_mut(),
        "activation exchange should include governing charter",
    )
    .kind = FederationArtifactKind::Listing;
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut exchange = sample_activation_exchange();
    exchange.delegation_control.delegator_operator_id = "other-operator".to_string();
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut exchange = sample_activation_exchange();
    exchange.delegation_control.delegate_operator_id = "other-operator".to_string();
    assert!(matches!(
        validate_federation_activation_exchange(&exchange),
        Err(FederationContractError::InvalidExchange(_))
    ));
}

#[test]
fn federation_helper_validators_reject_invalid_boundary_inputs() {
    let mut reference = sample_reference(
        FederationArtifactKind::Listing,
        "chio.registry.listing.v1",
        "listing-1",
        "origin-operator",
        'a',
    );
    reference.sha256 = "deadbeef".to_string();
    assert!(matches!(
        validate_federation_artifact_reference(&reference, "reference"),
        Err(FederationContractError::InvalidReference(_))
    ));

    let mut scope = sample_activation_exchange().scope;
    scope.allowed_actor_kinds.clear();
    assert!(matches!(
        validate_federation_scope(&scope),
        Err(FederationContractError::MissingField(_))
    ));

    let mut scope = sample_activation_exchange().scope;
    scope.allowed_admission_classes.clear();
    assert!(matches!(
        validate_federation_scope(&scope),
        Err(FederationContractError::MissingField(_))
    ));

    let mut scope = sample_activation_exchange().scope;
    scope.policy_reference = Some("   ".to_string());
    assert!(matches!(
        validate_federation_scope(&scope),
        Err(FederationContractError::MissingField(_))
    ));

    let mut control = sample_activation_exchange().delegation_control;
    control.delegate_operator_id = control.delegator_operator_id.clone();
    assert!(matches!(
        validate_delegation_control(&control),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut control = sample_activation_exchange().delegation_control;
    control.max_hops = 0;
    assert!(matches!(
        validate_delegation_control(&control),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut control = sample_activation_exchange().delegation_control;
    control.attenuation_required = false;
    assert!(matches!(
        validate_delegation_control(&control),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let mut control = sample_activation_exchange().delegation_control;
    control.visibility_only_until_local_activation = false;
    assert!(matches!(
        validate_delegation_control(&control),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let import = FederationImportControl {
        manual_review_required: false,
        ..Default::default()
    };
    assert!(matches!(
        validate_import_control(&import),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let import = FederationImportControl {
        reject_stale_inputs: false,
        ..Default::default()
    };
    assert!(matches!(
        validate_import_control(&import),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let import = FederationImportControl {
        allow_visibility_without_runtime_trust: false,
        ..Default::default()
    };
    assert!(matches!(
        validate_import_control(&import),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let import = FederationImportControl {
        prohibit_ambient_runtime_admission: false,
        ..Default::default()
    };
    assert!(matches!(
        validate_import_control(&import),
        Err(FederationContractError::InvalidExchange(_))
    ));

    let anti_eclipse = FederationAntiEclipsePolicy {
        minimum_distinct_operators: 0,
        ..Default::default()
    };
    assert!(matches!(
        validate_anti_eclipse_policy(&anti_eclipse),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    assert!(matches!(
        validate_positive_money(
            &MonetaryAmount {
                units: 0,
                currency: "USD".to_string(),
            },
            "bond"
        ),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    assert!(matches!(
        validate_positive_money(
            &MonetaryAmount {
                units: 10,
                currency: "US".to_string(),
            },
            "bond"
        ),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    assert!(matches!(
        validate_hex_digest("", "digest"),
        Err(FederationContractError::MissingField(_))
    ));

    assert!(matches!(
        validate_hex_digest("xyz", "digest"),
        Err(FederationContractError::InvalidReference(_))
    ));

    assert!(matches!(
        ensure_unique_strings(&["origin".to_string(), "origin".to_string()], "operators"),
        Err(FederationContractError::DuplicateValue(_))
    ));

    assert!(matches!(
        ensure_unique_copy_values(
            &[
                GenericTrustAdmissionClass::Reviewable,
                GenericTrustAdmissionClass::Reviewable,
            ],
            "classes"
        ),
        Err(FederationContractError::DuplicateValue(_))
    ));
}

#[test]
fn quorum_report_rejects_invalid_observations_and_policy_failures() {
    let mut report = sample_quorum_report();
    report.schema = "chio.federation-quorum-report.v0".to_string();
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::UnsupportedSchema(_))
    ));

    let mut report = sample_quorum_report();
    report.quorum_threshold = 0;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.max_replica_age_secs = 0;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.publishers.clear();
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::MissingField(_))
    ));

    let mut report = sample_quorum_report();
    report.publishers[0].report_ref.kind = FederationArtifactKind::Listing;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.publishers[0].report_ref.operator_id = "other-operator".to_string();
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.publishers[0].observed_listing_sha256 = "bad-digest".to_string();
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidReference(_))
    ));

    let mut report = sample_quorum_report();
    report.publishers[1].upstream_hop_count = 2;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.publishers[1].publisher.operator_id = report.publishers[0].publisher.operator_id.clone();
    report.publishers[1].report_ref.operator_id =
        report.publishers[0].publisher.operator_id.clone();
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut report = sample_quorum_report();
    report
        .publishers
        .retain(|publisher| publisher.publisher.role != GenericRegistryPublisherRole::Indexer);
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.anti_eclipse_policy.minimum_distinct_operators = 4;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));
}

#[test]
fn quorum_report_rejects_invalid_conflict_and_state_combinations() {
    let mut report = sample_quorum_report();
    report.conflicts = vec![sample_conflict(), sample_conflict()];
    report.final_state = FederationQuorumState::Conflicting;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut report = sample_quorum_report();
    report.conflicts.push(sample_conflict());
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.publishers[0].freshness.state = GenericListingFreshnessState::Stale;
    report.publishers[0].freshness.age_secs = 400;
    report.publishers[1].freshness.state = GenericListingFreshnessState::Stale;
    report.publishers[1].freshness.age_secs = 400;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.final_state = FederationQuorumState::Conflicting;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.final_state = FederationQuorumState::InsufficientQuorum;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));

    let mut report = sample_quorum_report();
    report.final_state = FederationQuorumState::Stale;
    report.publishers[0].freshness.state = GenericListingFreshnessState::Fresh;
    assert!(matches!(
        validate_federation_quorum_report(&report),
        Err(FederationContractError::InvalidQuorum(_))
    ));
}

#[test]
fn open_admission_policy_and_stake_rules_reject_invalid_configurations() {
    let mut policy = sample_open_admission_policy();
    policy.schema = "chio.federation-open-admission-policy.v0".to_string();
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::UnsupportedSchema(_))
    ));

    let mut policy = sample_open_admission_policy();
    policy.allowed_admission_classes.clear();
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::MissingField(_))
    ));

    let mut policy = sample_open_admission_policy();
    policy
        .allowed_admission_classes
        .push(GenericTrustAdmissionClass::Reviewable);
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut policy = sample_open_admission_policy();
    policy.governing_charter_ref.kind = FederationArtifactKind::Listing;
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut policy = sample_open_admission_policy();
    policy.fee_schedule_ref.kind = FederationArtifactKind::GovernanceCharter;
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut policy = sample_open_admission_policy();
    policy.explicit_local_review_required = false;
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut policy = sample_open_admission_policy();
    policy.visibility_only_without_activation = false;
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut policy = sample_open_admission_policy();
    policy.stake_requirements[0].admission_class = GenericTrustAdmissionClass::RoleGated;
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut policy = sample_open_admission_policy();
    let duplicate = policy.stake_requirements[0].clone();
    policy.stake_requirements.push(duplicate);
    assert!(matches!(
        validate_federated_open_admission_policy(&policy),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.minimum_bond_amount = None;
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.required_bond_class = None;
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.slashable = false;
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.minimum_bond_amount = Some(MonetaryAmount {
        units: 0,
        currency: "USD".to_string(),
    });
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.minimum_bond_amount = Some(MonetaryAmount {
        units: 10,
        currency: "US".to_string(),
    });
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.admission_class = GenericTrustAdmissionClass::PublicUntrusted;
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.admission_class = GenericTrustAdmissionClass::RoleGated;
    requirement.required_bond_class = None;
    requirement.minimum_bond_amount = None;
    requirement.governance_case_required = false;
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));

    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.admission_class = GenericTrustAdmissionClass::RoleGated;
    requirement.governance_case_required = true;
    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(_))
    ));
}

#[test]
fn federated_stake_requirement_rejects_lowercase_bond_currency() {
    let mut requirement = sample_open_admission_policy().stake_requirements[0].clone();
    requirement.minimum_bond_amount = Some(MonetaryAmount {
        units: 10,
        currency: "usd".to_string(),
    });

    assert!(matches!(
        validate_stake_requirement(&requirement),
        Err(FederationContractError::InvalidAdmission(message))
            if message.contains("currency")
    ));
}

#[test]
fn reputation_input_and_sybil_helpers_reject_invalid_values() {
    let clearing = sample_reputation_clearing();

    let mut input = clearing.inputs[0].clone();
    input.subject_key = "someone-else".to_string();
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut input = clearing.inputs[0].clone();
    input.weight_bps = 0;
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut input = clearing.inputs[0].clone();
    input.published_at = clearing.generated_at + 1;
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut input = clearing.inputs[0].clone();
    input.expires_at = Some(input.published_at);
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut input = clearing.inputs[0].clone();
    input.expires_at = Some(clearing.generated_at);
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut input = clearing.inputs[0].clone();
    input.issuer_independence_group_id = Some("   ".to_string());
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::MissingField(_))
    ));

    let mut input = clearing.inputs[0].clone();
    input.blocking = true;
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut input = clearing.inputs[0].clone();
    input.artifact_ref.kind = FederationArtifactKind::PortableNegativeEvent;
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut input = clearing.inputs[2].clone();
    input.artifact_ref.kind = FederationArtifactKind::PortableReputationSummary;
    assert!(matches!(
        validate_reputation_input_reference(&input, clearing.generated_at, &clearing.subject_key),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let sybil = FederatedSybilControl {
        minimum_independent_issuers: 0,
        ..Default::default()
    };
    assert!(matches!(
        validate_sybil_control(&sybil),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let sybil = FederatedSybilControl {
        maximum_inputs_per_issuer: 0,
        ..Default::default()
    };
    assert!(matches!(
        validate_sybil_control(&sybil),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let sybil = FederatedSybilControl {
        oracle_cap_bps: 10_001,
        ..Default::default()
    };
    assert!(matches!(
        validate_sybil_control(&sybil),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let sybil = FederatedSybilControl {
        local_weighting_required: false,
        ..Default::default()
    };
    assert!(matches!(
        validate_sybil_control(&sybil),
        Err(FederationContractError::InvalidClearing(_))
    ));
}

#[test]
fn reputation_clearing_rejects_invalid_classification_and_sybil_outcomes() {
    let mut clearing = sample_reputation_clearing();
    clearing.schema = "chio.federation-reputation-clearing.v0".to_string();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::UnsupportedSchema(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.participating_operator_ids.clear();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::MissingField(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.participating_operator_ids[1] = clearing.participating_operator_ids[0].clone();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.inputs.clear();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::MissingField(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing
        .accepted_input_ids
        .push("summary-origin-1".to_string());
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.rejected_input_ids = vec![
        "negative-origin-1".to_string(),
        "negative-origin-1".to_string(),
    ];
    clearing
        .accepted_input_ids
        .retain(|id| id != "negative-origin-1");
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing
        .rejected_input_ids
        .push("summary-origin-1".to_string());
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.accepted_input_ids.pop();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.inputs[1].issuer_operator_id = "origin-operator".to_string();
    clearing.inputs[1].artifact_ref.operator_id = "origin-operator".to_string();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.inputs[0].artifact_ref.operator_id = "other-operator".to_string();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.inputs[0].issuer_operator_id = "other-operator".to_string();
    clearing.inputs[0].artifact_ref.operator_id = "other-operator".to_string();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.inputs[0].weight_bps = 4_001;
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.accepted_input_ids = vec![
        "summary-origin-1".to_string(),
        "negative-origin-1".to_string(),
    ];
    clearing.rejected_input_ids = vec![
        "summary-mirror-a-1".to_string(),
        "negative-indexer-a-1".to_string(),
    ];
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.accepted_input_ids = vec![
        "summary-origin-1".to_string(),
        "summary-mirror-a-1".to_string(),
        "negative-indexer-a-1".to_string(),
    ];
    clearing.rejected_input_ids = vec!["negative-origin-1".to_string()];
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.sybil_control.minimum_independent_issuers = 3;
    clearing.inputs[1].issuer_independence_group_id =
        clearing.inputs[0].issuer_independence_group_id.clone();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    clearing.accepted_input_ids.clear();
    clearing.rejected_input_ids = clearing
        .inputs
        .iter()
        .map(|input| input.artifact_ref.artifact_id.clone())
        .collect();
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));

    let mut clearing = sample_reputation_clearing();
    let clearing_id = clearing.clearing_id.clone();
    must_some(
        clearing.continuity.as_mut(),
        "reputation clearing should include continuity",
    )
    .previous_clearing_id = Some(clearing_id);
    assert!(matches!(
        validate_federated_reputation_clearing(&clearing),
        Err(FederationContractError::InvalidClearing(_))
    ));
}

#[test]
fn qualification_matrix_rejects_case_level_misconfigurations() {
    let mut matrix = sample_qualification_matrix();
    matrix.schema = "chio.federation-qualification-matrix.v0".to_string();
    assert!(matches!(
        validate_federation_qualification_matrix(&matrix),
        Err(FederationContractError::UnsupportedSchema(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases.clear();
    assert!(matches!(
        validate_federation_qualification_matrix(&matrix),
        Err(FederationContractError::MissingField(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].requirement_ids.clear();
    assert!(matches!(
        validate_federation_qualification_matrix(&matrix),
        Err(FederationContractError::InvalidQualificationCase(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0]
        .requirement_ids
        .push("TRUSTMAX-01".to_string());
    assert!(matches!(
        validate_federation_qualification_matrix(&matrix),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[1].id = matrix.cases[0].id.clone();
    assert!(matches!(
        validate_federation_qualification_matrix(&matrix),
        Err(FederationContractError::DuplicateValue(_))
    ));

    let mut matrix = sample_qualification_matrix();
    matrix.cases[0].notes.clear();
    assert!(matches!(
        validate_federation_qualification_matrix(&matrix),
        Err(FederationContractError::MissingField(_))
    ));
}
