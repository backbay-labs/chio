use crate::capability::scope::MonetaryAmount;
use crate::crypto::Keypair;
use crate::evaluation::{evaluate_open_market_penalty, OpenMarketPenaltyEvaluationRequest};
use crate::evidence::{OpenMarketEvidenceKind, OpenMarketEvidenceReference, OpenMarketFindingCode};
use crate::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleArtifact,
    OpenMarketFeeScheduleIssueRequest, SignedOpenMarketFeeSchedule,
    OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA,
};
use crate::fiscal_adapter::{
    signed_fee_schedule_digest, verify_fiscal_legacy_binding, FiscalLegacyFeeScheduleBinding,
    FiscalOpenMarketError,
};
use crate::governance::generic::{
    build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
    GenericGovernanceAuthorityScope, GenericGovernanceCaseIssueRequest, GenericGovernanceCaseKind,
    GenericGovernanceCaseState, GenericGovernanceCharterIssueRequest,
    GenericGovernanceEvidenceKind, GenericGovernanceEvidenceReference, SignedGenericGovernanceCase,
    SignedGenericGovernanceCharter,
};
use crate::listing::{
    build_generic_trust_activation_artifact, GenericListingActorKind, GenericListingArtifact,
    GenericListingBoundary, GenericListingCompatibilityReference, GenericListingFreshnessState,
    GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
    GenericNamespaceArtifact, GenericNamespaceLifecycleState, GenericNamespaceOwnership,
    GenericRegistryPublisher, GenericRegistryPublisherRole, GenericTrustActivationDisposition,
    GenericTrustActivationEligibility, GenericTrustActivationIssueRequest,
    GenericTrustActivationReviewContext, GenericTrustAdmissionClass, SignedGenericListing,
    SignedGenericTrustActivation, GENERIC_LISTING_ARTIFACT_SCHEMA,
    GENERIC_NAMESPACE_ARTIFACT_SCHEMA,
};
use crate::penalty::{
    build_open_market_penalty_artifact, build_open_market_penalty_artifact_with_trusted_signers,
    OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyArtifact,
    OpenMarketPenaltyEffectiveState, OpenMarketPenaltyIssueRequest, OpenMarketPenaltyState,
    SignedOpenMarketPenalty, OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA,
};

use chio_test_support::prelude::*;

fn sample_listing(owner_id: &str, signing_keypair: &Keypair) -> SignedGenericListing {
    let namespace = GenericNamespaceArtifact {
        schema: GENERIC_NAMESPACE_ARTIFACT_SCHEMA.to_string(),
        namespace_id: "namespace-registry-chio-example".to_string(),
        lifecycle_state: GenericNamespaceLifecycleState::Active,
        ownership: GenericNamespaceOwnership {
            namespace: "https://registry.chio.example".to_string(),
            owner_id: owner_id.to_string(),
            owner_name: Some("Registry Operator".to_string()),
            registry_url: "https://registry.chio.example".to_string(),
            signer_public_key: signing_keypair.public_key(),
            registered_at: 100,
            transferred_from_owner_id: None,
        },
        boundary: GenericListingBoundary::default(),
    };
    let listing = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: "listing-demo".to_string(),
        namespace: namespace.ownership.namespace.clone(),
        published_at: 200,
        expires_at: Some(500),
        status: GenericListingStatus::Active,
        namespace_ownership: namespace.ownership.clone(),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: "demo-server".to_string(),
            display_name: Some("Demo Server".to_string()),
            metadata_url: Some("https://registry.chio.example/servers/demo".to_string()),
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: "cert-check-demo".to_string(),
            source_artifact_sha256: "sha256-demo".to_string(),
        },
        boundary: GenericListingBoundary::default(),
    };
    SignedGenericListing::sign(listing, signing_keypair).test_expect("sign listing")
}

fn sample_publisher(owner_id: &str) -> GenericRegistryPublisher {
    GenericRegistryPublisher {
        role: GenericRegistryPublisherRole::Origin,
        operator_id: owner_id.to_string(),
        operator_name: Some("Registry Operator".to_string()),
        registry_url: "https://registry.chio.example".to_string(),
        upstream_registry_urls: Vec::new(),
    }
}

fn sample_activation(
    owner_id: &str,
    signing_keypair: &Keypair,
    listing: &SignedGenericListing,
) -> SignedGenericTrustActivation {
    let artifact = build_generic_trust_activation_artifact(
        owner_id,
        Some("Registry Operator".to_string()),
        &GenericTrustActivationIssueRequest {
            listing: listing.clone(),
            admission_class: GenericTrustAdmissionClass::BondBacked,
            disposition: GenericTrustActivationDisposition::Approved,
            eligibility: GenericTrustActivationEligibility {
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
                allowed_statuses: vec![GenericListingStatus::Active],
                require_fresh_listing: true,
                require_bond_backing: true,
                required_listing_operator_ids: vec![owner_id.to_string()],
                policy_reference: Some("policy/open-market/default".to_string()),
            },
            review_context: GenericTrustActivationReviewContext {
                publisher: sample_publisher(owner_id),
                freshness: GenericListingReplicaFreshness {
                    state: GenericListingFreshnessState::Fresh,
                    age_secs: 0,
                    max_age_secs: 300,
                    valid_until: 500,
                    generated_at: 200,
                },
            },
            requested_by: "ops@chio.example".to_string(),
            reviewed_by: Some("reviewer@chio.example".to_string()),
            requested_at: Some(200),
            reviewed_at: Some(201),
            expires_at: Some(450),
            note: None,
        },
        200,
    )
    .test_expect("build activation");
    SignedGenericTrustActivation::sign(artifact, signing_keypair).test_expect("sign activation")
}

fn sample_charter(owner_id: &str, signing_keypair: &Keypair) -> SignedGenericGovernanceCharter {
    let artifact = build_generic_governance_charter_artifact(
        owner_id,
        Some("Registry Operator".to_string()),
        &GenericGovernanceCharterIssueRequest {
            authority_scope: GenericGovernanceAuthorityScope {
                namespace: "https://registry.chio.example".to_string(),
                allowed_listing_operator_ids: vec![owner_id.to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                policy_reference: Some("policy/governance/default".to_string()),
            },
            allowed_case_kinds: vec![
                GenericGovernanceCaseKind::Sanction,
                GenericGovernanceCaseKind::Appeal,
            ],
            escalation_operator_ids: Vec::new(),
            issued_by: "governance@chio.example".to_string(),
            issued_at: Some(202),
            expires_at: Some(600),
            note: None,
        },
        202,
    )
    .test_expect("build charter");
    SignedGenericGovernanceCharter::sign(artifact, signing_keypair).test_expect("sign charter")
}

fn sample_sanction_case(
    owner_id: &str,
    signing_keypair: &Keypair,
    listing: &SignedGenericListing,
    activation: &SignedGenericTrustActivation,
    charter: &SignedGenericGovernanceCharter,
) -> SignedGenericGovernanceCase {
    let artifact = build_generic_governance_case_artifact(
        owner_id,
        &GenericGovernanceCaseIssueRequest {
            charter: charter.clone(),
            listing: listing.clone(),
            activation: Some(activation.clone()),
            kind: GenericGovernanceCaseKind::Sanction,
            state: GenericGovernanceCaseState::Enforced,
            subject_operator_id: Some(owner_id.to_string()),
            escalated_to_operator_ids: Vec::new(),
            evidence_refs: vec![GenericGovernanceEvidenceReference {
                kind: GenericGovernanceEvidenceKind::TrustActivation,
                reference_id: activation.body.activation_id.clone(),
                uri: None,
                sha256: None,
            }],
            appeal_of_case_id: None,
            supersedes_case_id: None,
            issued_by: "governance@chio.example".to_string(),
            opened_at: Some(203),
            updated_at: Some(203),
            expires_at: Some(500),
            note: None,
        },
        203,
    )
    .test_expect("build case");
    SignedGenericGovernanceCase::sign(artifact, signing_keypair).test_expect("sign case")
}

fn sample_fee_schedule(owner_id: &str, signing_keypair: &Keypair) -> SignedOpenMarketFeeSchedule {
    let artifact = build_open_market_fee_schedule_artifact(
        owner_id,
        Some("Registry Operator".to_string()),
        &OpenMarketFeeScheduleIssueRequest {
            scope: OpenMarketEconomicsScope {
                namespace: "https://registry.chio.example".to_string(),
                allowed_listing_operator_ids: vec![owner_id.to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                policy_reference: Some("policy/open-market/default".to_string()),
            },
            publication_fee: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            dispute_fee: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            market_participation_fee: MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            },
            bond_requirements: vec![OpenMarketBondRequirement {
                bond_class: OpenMarketBondClass::Listing,
                required_amount: MonetaryAmount {
                    units: 5000,
                    currency: "USD".to_string(),
                },
                collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                slashable: true,
            }],
            issued_by: "market@chio.example".to_string(),
            issued_at: Some(202),
            expires_at: Some(600),
            note: None,
        },
        202,
    )
    .test_expect("build fee schedule");
    SignedOpenMarketFeeSchedule::sign(artifact, signing_keypair).test_expect("sign fee schedule")
}

fn sample_penalty_issue_request(
    owner_id: &str,
    fee_schedule: SignedOpenMarketFeeSchedule,
    charter: SignedGenericGovernanceCharter,
    case: SignedGenericGovernanceCase,
    listing: SignedGenericListing,
    activation: Option<SignedGenericTrustActivation>,
) -> OpenMarketPenaltyIssueRequest {
    OpenMarketPenaltyIssueRequest {
        fee_schedule,
        charter,
        case,
        listing,
        activation,
        abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
        bond_class: OpenMarketBondClass::Listing,
        action: OpenMarketPenaltyAction::SlashBond,
        state: OpenMarketPenaltyState::Enforced,
        penalty_amount: MonetaryAmount {
            units: 2500,
            currency: "USD".to_string(),
        },
        evidence_refs: vec![OpenMarketEvidenceReference {
            kind: OpenMarketEvidenceKind::GovernanceCase,
            reference_id: "case-ref".to_string(),
            uri: None,
            sha256: None,
        }],
        subject_operator_id: Some(owner_id.to_string()),
        supersedes_penalty_id: None,
        issued_by: "market@chio.example".to_string(),
        opened_at: Some(204),
        updated_at: Some(204),
        expires_at: Some(500),
        note: None,
    }
}

#[test]
fn open_market_evaluation_applies_fee_schedule_and_slash_penalty() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
    let penalty_artifact = build_open_market_penalty_artifact(
        owner_id,
        &OpenMarketPenaltyIssueRequest {
            fee_schedule: fee_schedule.clone(),
            charter: charter.clone(),
            case: governance_case.clone(),
            listing: listing.clone(),
            activation: Some(activation.clone()),
            abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
            bond_class: OpenMarketBondClass::Listing,
            action: OpenMarketPenaltyAction::SlashBond,
            state: OpenMarketPenaltyState::Enforced,
            penalty_amount: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::GovernanceCase,
                reference_id: governance_case.body.case_id.clone(),
                uri: None,
                sha256: None,
            }],
            subject_operator_id: Some(owner_id.to_string()),
            supersedes_penalty_id: None,
            issued_by: "market@chio.example".to_string(),
            opened_at: Some(204),
            updated_at: Some(204),
            expires_at: Some(500),
            note: None,
        },
        204,
        &signing_keypair.public_key(),
    )
    .test_expect("build penalty");
    let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
        .test_expect("sign penalty");

    let evaluation = evaluate_open_market_penalty(
        &OpenMarketPenaltyEvaluationRequest {
            fee_schedule,
            listing,
            current_publisher: sample_publisher(owner_id),
            activation: Some(activation),
            charter,
            case: governance_case,
            penalty,
            prior_penalty: None,
            evaluated_at: Some(205),
        },
        205,
        &signing_keypair.public_key(),
    )
    .test_expect("evaluate open market");

    assert_eq!(
        evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::BondSlashed
    );
    assert!(evaluation.blocks_admission);
    assert!(evaluation.findings.is_empty());
    assert_eq!(
        evaluation
            .publication_fee
            .as_ref()
            .test_expect("publication fee")
            .units,
        100
    );
    assert_eq!(
        evaluation
            .bond_requirement
            .as_ref()
            .test_expect("bond requirement")
            .bond_class,
        OpenMarketBondClass::Listing
    );
}

#[test]
fn open_market_penalty_issue_accepts_rotated_trusted_authority_signers() {
    let previous_keypair = Keypair::from_seed(&[7_u8; 32]);
    let current_keypair = Keypair::from_seed(&[8_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &previous_keypair);
    let activation = sample_activation(owner_id, &current_keypair, &listing);
    let charter = sample_charter(owner_id, &current_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &current_keypair, &listing, &activation, &charter);
    let fee_schedule = sample_fee_schedule(owner_id, &previous_keypair);
    let request = sample_penalty_issue_request(
        owner_id,
        fee_schedule,
        charter,
        governance_case,
        listing,
        Some(activation),
    );

    let artifact = build_open_market_penalty_artifact_with_trusted_signers(
        owner_id,
        &request,
        204,
        &[previous_keypair.public_key(), current_keypair.public_key()],
    )
    .test_expect("rotated trusted signer set should issue penalty");

    assert_eq!(artifact.governing_operator_id, owner_id);
}

#[test]
fn open_market_evaluation_rejects_expired_fee_schedule() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let mut fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
    fee_schedule.body.expires_at = Some(204);
    let fee_schedule = SignedOpenMarketFeeSchedule::sign(fee_schedule.body, &signing_keypair)
        .test_expect("resign");
    let penalty_artifact = build_open_market_penalty_artifact(
        owner_id,
        &OpenMarketPenaltyIssueRequest {
            fee_schedule: fee_schedule.clone(),
            charter: charter.clone(),
            case: governance_case.clone(),
            listing: listing.clone(),
            activation: Some(activation.clone()),
            abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
            bond_class: OpenMarketBondClass::Listing,
            action: OpenMarketPenaltyAction::HoldBond,
            state: OpenMarketPenaltyState::Enforced,
            penalty_amount: MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            },
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::GovernanceCase,
                reference_id: governance_case.body.case_id.clone(),
                uri: None,
                sha256: None,
            }],
            subject_operator_id: Some(owner_id.to_string()),
            supersedes_penalty_id: None,
            issued_by: "market@chio.example".to_string(),
            opened_at: Some(204),
            updated_at: Some(204),
            expires_at: Some(500),
            note: None,
        },
        204,
        &signing_keypair.public_key(),
    )
    .test_expect("build penalty");
    let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
        .test_expect("sign penalty");

    let evaluation = evaluate_open_market_penalty(
        &OpenMarketPenaltyEvaluationRequest {
            fee_schedule,
            listing,
            current_publisher: sample_publisher(owner_id),
            activation: Some(activation),
            charter,
            case: governance_case,
            penalty,
            prior_penalty: None,
            evaluated_at: Some(205),
        },
        205,
        &signing_keypair.public_key(),
    )
    .test_expect("evaluate open market");

    assert_eq!(evaluation.findings.len(), 1);
    assert_eq!(
        evaluation.findings[0].code,
        OpenMarketFindingCode::FeeScheduleExpired
    );
}

#[test]
fn open_market_evaluation_rejects_missing_bond_requirement() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let artifact = build_open_market_fee_schedule_artifact(
        owner_id,
        Some("Registry Operator".to_string()),
        &OpenMarketFeeScheduleIssueRequest {
            scope: OpenMarketEconomicsScope {
                namespace: "https://registry.chio.example".to_string(),
                allowed_listing_operator_ids: vec![owner_id.to_string()],
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
                policy_reference: Some("policy/open-market/default".to_string()),
            },
            publication_fee: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            dispute_fee: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            market_participation_fee: MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            },
            bond_requirements: vec![OpenMarketBondRequirement {
                bond_class: OpenMarketBondClass::Dispute,
                required_amount: MonetaryAmount {
                    units: 5000,
                    currency: "USD".to_string(),
                },
                collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
                slashable: true,
            }],
            issued_by: "market@chio.example".to_string(),
            issued_at: Some(202),
            expires_at: Some(600),
            note: None,
        },
        202,
    )
    .test_expect("build fee schedule");
    let fee_schedule = SignedOpenMarketFeeSchedule::sign(artifact, &signing_keypair)
        .test_expect("sign fee schedule");
    let penalty_artifact = build_open_market_penalty_artifact(
        owner_id,
        &OpenMarketPenaltyIssueRequest {
            fee_schedule: fee_schedule.clone(),
            charter: charter.clone(),
            case: governance_case.clone(),
            listing: listing.clone(),
            activation: Some(activation.clone()),
            abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
            bond_class: OpenMarketBondClass::Listing,
            action: OpenMarketPenaltyAction::HoldBond,
            state: OpenMarketPenaltyState::Enforced,
            penalty_amount: MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            },
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::GovernanceCase,
                reference_id: governance_case.body.case_id.clone(),
                uri: None,
                sha256: None,
            }],
            subject_operator_id: Some(owner_id.to_string()),
            supersedes_penalty_id: None,
            issued_by: "market@chio.example".to_string(),
            opened_at: Some(204),
            updated_at: Some(204),
            expires_at: Some(500),
            note: None,
        },
        204,
        &signing_keypair.public_key(),
    )
    .test_expect("build penalty");
    let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
        .test_expect("sign penalty");

    let evaluation = evaluate_open_market_penalty(
        &OpenMarketPenaltyEvaluationRequest {
            fee_schedule,
            listing,
            current_publisher: sample_publisher(owner_id),
            activation: Some(activation),
            charter,
            case: governance_case,
            penalty,
            prior_penalty: None,
            evaluated_at: Some(205),
        },
        205,
        &signing_keypair.public_key(),
    )
    .test_expect("evaluate open market");

    assert_eq!(evaluation.findings.len(), 1);
    assert_eq!(
        evaluation.findings[0].code,
        OpenMarketFindingCode::BondRequirementMissing
    );
}

#[test]
fn open_market_penalty_issue_rejects_non_local_activation_authority() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let mut forged_activation_body = activation.body.clone();
    forged_activation_body.local_operator_id = "https://remote.chio.example".to_string();
    forged_activation_body.local_operator_name = Some("Remote Operator".to_string());
    let forged_activation =
        SignedGenericTrustActivation::sign(forged_activation_body, &signing_keypair)
            .test_expect("sign forged activation");
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);

    let error = build_open_market_penalty_artifact(
        owner_id,
        &OpenMarketPenaltyIssueRequest {
            fee_schedule,
            charter,
            case: governance_case.clone(),
            listing,
            activation: Some(forged_activation),
            abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
            bond_class: OpenMarketBondClass::Listing,
            action: OpenMarketPenaltyAction::SlashBond,
            state: OpenMarketPenaltyState::Enforced,
            penalty_amount: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::GovernanceCase,
                reference_id: governance_case.body.case_id,
                uri: None,
                sha256: None,
            }],
            subject_operator_id: Some(owner_id.to_string()),
            supersedes_penalty_id: None,
            issued_by: "market@chio.example".to_string(),
            opened_at: Some(204),
            updated_at: Some(204),
            expires_at: Some(500),
            note: None,
        },
        204,
        &signing_keypair.public_key(),
    )
    .test_expect_err("non-local activation authority rejected");
    assert!(error.contains("issued by the governing operator"));
}

#[test]
fn open_market_evaluation_rejects_non_local_activation_authority() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
    let penalty_artifact = build_open_market_penalty_artifact(
        owner_id,
        &OpenMarketPenaltyIssueRequest {
            fee_schedule: fee_schedule.clone(),
            charter: charter.clone(),
            case: governance_case.clone(),
            listing: listing.clone(),
            activation: Some(activation.clone()),
            abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
            bond_class: OpenMarketBondClass::Listing,
            action: OpenMarketPenaltyAction::SlashBond,
            state: OpenMarketPenaltyState::Enforced,
            penalty_amount: MonetaryAmount {
                units: 2500,
                currency: "USD".to_string(),
            },
            evidence_refs: vec![OpenMarketEvidenceReference {
                kind: OpenMarketEvidenceKind::GovernanceCase,
                reference_id: governance_case.body.case_id.clone(),
                uri: None,
                sha256: None,
            }],
            subject_operator_id: Some(owner_id.to_string()),
            supersedes_penalty_id: None,
            issued_by: "market@chio.example".to_string(),
            opened_at: Some(204),
            updated_at: Some(204),
            expires_at: Some(500),
            note: None,
        },
        204,
        &signing_keypair.public_key(),
    )
    .test_expect("build penalty");
    let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
        .test_expect("sign penalty");
    let mut forged_activation_body = activation.body.clone();
    forged_activation_body.local_operator_id = "https://remote.chio.example".to_string();
    forged_activation_body.local_operator_name = Some("Remote Operator".to_string());
    let forged_activation =
        SignedGenericTrustActivation::sign(forged_activation_body, &signing_keypair)
            .test_expect("sign forged activation");

    let evaluation = evaluate_open_market_penalty(
        &OpenMarketPenaltyEvaluationRequest {
            fee_schedule,
            listing,
            current_publisher: sample_publisher(owner_id),
            activation: Some(forged_activation),
            charter,
            case: governance_case,
            penalty,
            prior_penalty: None,
            evaluated_at: Some(205),
        },
        205,
        &signing_keypair.public_key(),
    )
    .test_expect("evaluate open market");

    assert_eq!(evaluation.findings.len(), 1);
    assert_eq!(
        evaluation.findings[0].code,
        OpenMarketFindingCode::ActivationMismatch
    );
}

#[test]
fn open_market_scope_rejects_blank_operator_ids() {
    let error = OpenMarketEconomicsScope {
        namespace: "https://registry.chio.example".to_string(),
        allowed_listing_operator_ids: vec!["   ".to_string()],
        allowed_actor_kinds: Vec::new(),
        allowed_admission_classes: Vec::new(),
        policy_reference: None,
    }
    .validate()
    .test_expect_err("blank operator ids rejected");

    assert!(error.contains("scope.allowed_listing_operator_ids[0]"));
}

#[test]
fn open_market_evidence_reference_rejects_invalid_sha256() {
    let error = OpenMarketEvidenceReference {
        kind: OpenMarketEvidenceKind::External,
        reference_id: "incident-1".to_string(),
        uri: None,
        sha256: Some("not-a-digest".to_string()),
    }
    .validate("evidence")
    .test_expect_err("invalid evidence sha256 rejected");

    assert!(error.contains("evidence.sha256"));
}

#[test]
fn open_market_fee_schedule_validate_rejects_namespace_mismatch() {
    let error = OpenMarketFeeScheduleArtifact {
        schema: OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA.to_string(),
        fee_schedule_id: "fee-1".to_string(),
        namespace: "https://registry.chio.example".to_string(),
        governing_operator_id: "https://registry.chio.example".to_string(),
        governing_operator_name: Some("Registry Operator".to_string()),
        scope: OpenMarketEconomicsScope {
            namespace: "https://different.chio.example".to_string(),
            allowed_listing_operator_ids: vec!["https://registry.chio.example".to_string()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
            policy_reference: None,
        },
        publication_fee: MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        },
        dispute_fee: MonetaryAmount {
            units: 2500,
            currency: "USD".to_string(),
        },
        market_participation_fee: MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        },
        bond_requirements: vec![OpenMarketBondRequirement {
            bond_class: OpenMarketBondClass::Listing,
            required_amount: MonetaryAmount {
                units: 5000,
                currency: "USD".to_string(),
            },
            collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
            slashable: true,
        }],
        issued_at: 100,
        expires_at: Some(200),
        issued_by: "market@chio.example".to_string(),
        note: None,
    }
    .validate()
    .test_expect_err("namespace mismatch rejected");

    assert!(error.contains("namespace must match scope namespace"));
}

#[test]
fn open_market_fee_schedule_issue_request_requires_bond_requirements() {
    let error = OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: "https://registry.chio.example".to_string(),
            allowed_listing_operator_ids: vec!["https://registry.chio.example".to_string()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
            policy_reference: None,
        },
        publication_fee: MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        },
        dispute_fee: MonetaryAmount {
            units: 2500,
            currency: "USD".to_string(),
        },
        market_participation_fee: MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        },
        bond_requirements: Vec::new(),
        issued_by: "market@chio.example".to_string(),
        issued_at: Some(202),
        expires_at: Some(600),
        note: None,
    }
    .validate()
    .test_expect_err("bond requirements required");

    assert!(error.contains("bond_requirements must not be empty"));
}

#[test]
fn open_market_penalty_validate_requires_reverse_slash_metadata() {
    let error = OpenMarketPenaltyArtifact {
        schema: OPEN_MARKET_PENALTY_ARTIFACT_SCHEMA.to_string(),
        penalty_id: "penalty-1".to_string(),
        fee_schedule_id: "fee-1".to_string(),
        charter_id: "charter-1".to_string(),
        case_id: "case-1".to_string(),
        governing_operator_id: "https://registry.chio.example".to_string(),
        namespace: "https://registry.chio.example".to_string(),
        listing_id: "listing-demo".to_string(),
        activation_id: Some("activation-1".to_string()),
        subject_operator_id: Some("https://registry.chio.example".to_string()),
        abuse_class: OpenMarketAbuseClass::UnverifiableListingBehavior,
        bond_class: OpenMarketBondClass::Listing,
        action: OpenMarketPenaltyAction::ReverseSlash,
        state: OpenMarketPenaltyState::Enforced,
        penalty_amount: MonetaryAmount {
            units: 2500,
            currency: "USD".to_string(),
        },
        opened_at: 100,
        updated_at: 100,
        expires_at: Some(200),
        evidence_refs: vec![OpenMarketEvidenceReference {
            kind: OpenMarketEvidenceKind::GovernanceCase,
            reference_id: "case-1".to_string(),
            uri: None,
            sha256: None,
        }],
        supersedes_penalty_id: None,
        issued_by: "market@chio.example".to_string(),
        note: None,
    }
    .validate()
    .test_expect_err("reverse slash metadata required");

    assert!(error.contains("requires supersedes_penalty_id"));
}

#[test]
fn open_market_penalty_issue_request_rejects_invalid_fee_schedule_signature() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
    let mut tampered_fee_schedule = fee_schedule.clone();
    tampered_fee_schedule.body.publication_fee.units += 1;

    let error = sample_penalty_issue_request(
        owner_id,
        tampered_fee_schedule,
        charter,
        governance_case,
        listing,
        Some(activation),
    )
    .validate()
    .test_expect_err("tampered fee schedule rejected");

    assert!(error.contains("fee schedule signature is invalid"));
}

#[test]
fn open_market_penalty_issue_request_rejects_mismatched_authority_signer() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let attacker_keypair = Keypair::from_seed(&[8_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let forged_charter =
        SignedGenericGovernanceCharter::sign(charter.body.clone(), &attacker_keypair)
            .test_expect("sign forged charter");
    let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);

    let request = sample_penalty_issue_request(
        owner_id,
        fee_schedule,
        forged_charter,
        governance_case,
        listing,
        Some(activation),
    );

    let error =
        build_open_market_penalty_artifact(owner_id, &request, 204, &signing_keypair.public_key())
            .test_expect_err("mismatched governing signer rejected");

    assert!(error.contains("governing authority signer"));
}

#[test]
fn build_open_market_fee_schedule_artifact_uses_request_issued_at() {
    let owner_id = "https://registry.chio.example";
    let mut request = OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: "https://registry.chio.example".to_string(),
            allowed_listing_operator_ids: vec![owner_id.to_string()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            allowed_admission_classes: vec![GenericTrustAdmissionClass::BondBacked],
            policy_reference: Some("policy/open-market/default".to_string()),
        },
        publication_fee: MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        },
        dispute_fee: MonetaryAmount {
            units: 2500,
            currency: "USD".to_string(),
        },
        market_participation_fee: MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        },
        bond_requirements: vec![OpenMarketBondRequirement {
            bond_class: OpenMarketBondClass::Listing,
            required_amount: MonetaryAmount {
                units: 5000,
                currency: "USD".to_string(),
            },
            collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
            slashable: true,
        }],
        issued_by: "market@chio.example".to_string(),
        issued_at: Some(777),
        expires_at: Some(900),
        note: None,
    };
    let artifact = build_open_market_fee_schedule_artifact(
        owner_id,
        Some("Registry Operator".to_string()),
        &request,
        202,
    )
    .test_expect("build fee schedule");

    assert_eq!(artifact.issued_at, 777);
    assert_eq!(artifact.governing_operator_id, owner_id);
    assert!(artifact.fee_schedule_id.starts_with("market-fee-"));
    request.issued_at = Some(778);
    let changed = build_open_market_fee_schedule_artifact(
        owner_id,
        Some("Registry Operator".to_string()),
        &request,
        202,
    )
    .test_expect("build changed fee schedule");
    assert_ne!(artifact.fee_schedule_id, changed.fee_schedule_id);
}

#[test]
fn fiscal_legacy_binding_requires_the_exact_signed_envelope_and_body() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let schedule = sample_fee_schedule("https://registry.chio.example", &signing_keypair);
    let binding = FiscalLegacyFeeScheduleBinding {
        fiscal_schedule_id: "fiscal-schedule-1".to_owned(),
        legacy_envelope_digest: signed_fee_schedule_digest(&schedule)
            .test_expect("digest fee schedule"),
    };
    verify_fiscal_legacy_binding(
        &schedule,
        &binding,
        "fiscal-schedule-1",
        &schedule.body,
        &[signing_keypair.public_key()],
    )
    .test_expect("verify exact fiscal binding");

    let mut mismatched_body = schedule.body.clone();
    mismatched_body.publication_fee.units += 1;
    assert!(matches!(
        verify_fiscal_legacy_binding(
            &schedule,
            &binding,
            "fiscal-schedule-1",
            &mismatched_body,
            &[signing_keypair.public_key()],
        ),
        Err(FiscalOpenMarketError::BindingMismatch)
    ));

    let wrong_signer = Keypair::from_seed(&[8_u8; 32]);
    assert!(matches!(
        verify_fiscal_legacy_binding(
            &schedule,
            &binding,
            "fiscal-schedule-1",
            &schedule.body,
            &[wrong_signer.public_key()],
        ),
        Err(FiscalOpenMarketError::InvalidLegacySchedule(_))
    ));
}

#[test]
fn open_market_evaluation_rejects_invalid_penalty_signature() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
    let penalty_artifact = build_open_market_penalty_artifact(
        owner_id,
        &sample_penalty_issue_request(
            owner_id,
            fee_schedule.clone(),
            charter.clone(),
            governance_case.clone(),
            listing.clone(),
            Some(activation.clone()),
        ),
        204,
        &signing_keypair.public_key(),
    )
    .test_expect("build penalty");
    let penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &signing_keypair)
        .test_expect("sign penalty");
    let mut tampered_penalty = penalty.clone();
    tampered_penalty.body.note = Some("tampered".to_string());

    let evaluation = evaluate_open_market_penalty(
        &OpenMarketPenaltyEvaluationRequest {
            fee_schedule,
            listing,
            current_publisher: sample_publisher(owner_id),
            activation: Some(activation),
            charter,
            case: governance_case,
            penalty: tampered_penalty,
            prior_penalty: None,
            evaluated_at: Some(205),
        },
        205,
        &signing_keypair.public_key(),
    )
    .test_expect("evaluate open market");

    assert_eq!(
        evaluation.findings[0].code,
        OpenMarketFindingCode::PenaltyUnverifiable
    );
}

#[test]
fn open_market_evaluation_rejects_mismatched_authority_signer() {
    let signing_keypair = Keypair::from_seed(&[7_u8; 32]);
    let attacker_keypair = Keypair::from_seed(&[8_u8; 32]);
    let owner_id = "https://registry.chio.example";
    let listing = sample_listing(owner_id, &signing_keypair);
    let activation = sample_activation(owner_id, &signing_keypair, &listing);
    let charter = sample_charter(owner_id, &signing_keypair);
    let governance_case =
        sample_sanction_case(owner_id, &signing_keypair, &listing, &activation, &charter);
    let fee_schedule = sample_fee_schedule(owner_id, &signing_keypair);
    let penalty_artifact = build_open_market_penalty_artifact(
        owner_id,
        &sample_penalty_issue_request(
            owner_id,
            fee_schedule.clone(),
            charter.clone(),
            governance_case.clone(),
            listing.clone(),
            Some(activation.clone()),
        ),
        204,
        &signing_keypair.public_key(),
    )
    .test_expect("build penalty");
    let forged_penalty = SignedOpenMarketPenalty::sign(penalty_artifact, &attacker_keypair)
        .test_expect("sign forged penalty");

    let evaluation = evaluate_open_market_penalty(
        &OpenMarketPenaltyEvaluationRequest {
            fee_schedule,
            listing,
            current_publisher: sample_publisher(owner_id),
            activation: Some(activation),
            charter,
            case: governance_case,
            penalty: forged_penalty,
            prior_penalty: None,
            evaluated_at: Some(205),
        },
        205,
        &signing_keypair.public_key(),
    )
    .test_expect("evaluate open market");

    assert_eq!(evaluation.findings.len(), 1);
    assert_eq!(
        evaluation.findings[0].code,
        OpenMarketFindingCode::GovernanceCaseAuthorityInvalid
    );
    assert!(evaluation.findings[0]
        .message
        .contains("governing authority signer"));
}
