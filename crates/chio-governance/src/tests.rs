use crate::authorization::{
    verify_destructive_authorization, verify_step_governance_boundary, GovernanceReceiptArtifact,
    GovernanceReceiptCaseKind, SignedGovernanceReceipt, GOVERNANCE_RECEIPT_SCHEMA_V1,
};
use crate::crypto::Keypair;
use crate::error::GovernanceAuthorizationError;
use crate::evaluation::evaluate_generic_governance_case;
use crate::generic::{
    build_generic_governance_case_artifact, build_generic_governance_charter_artifact,
    GenericGovernanceAuthorityScope, GenericGovernanceCaseArtifact,
    GenericGovernanceCaseEvaluationRequest, GenericGovernanceCaseIssueRequest,
    GenericGovernanceCaseKind, GenericGovernanceCaseState, GenericGovernanceCharterArtifact,
    GenericGovernanceCharterIssueRequest, GenericGovernanceEffectiveState,
    GenericGovernanceEvidenceKind, GenericGovernanceEvidenceReference,
    GenericGovernanceFindingCode, SignedGenericGovernanceCase, SignedGenericGovernanceCharter,
    GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA, GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA,
};
use crate::lease::{
    verify_capability_lease, CapabilityLeaseActionClass, CapabilityLeaseArtifact,
    SignedCapabilityLease, CAPABILITY_LEASE_SCHEMA_V1,
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
use crate::validation::is_sha256_hex;

use chio_test_support::prelude::*;

fn sample_namespace(owner_id: &str, signing_keypair: &Keypair) -> GenericNamespaceArtifact {
    GenericNamespaceArtifact {
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
    }
}

fn sample_listing(owner_id: &str, signing_keypair: &Keypair) -> GenericListingArtifact {
    GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: "listing-artifact-1".to_string(),
        namespace: "https://registry.chio.example".to_string(),
        namespace_ownership: sample_namespace(owner_id, signing_keypair).ownership,
        published_at: 110,
        expires_at: Some(1_000),
        status: GenericListingStatus::Active,
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: "tool-server-a".to_string(),
            display_name: Some("Tool Server A".to_string()),
            metadata_url: Some("https://tool.chio.example/metadata".to_string()),
            resolution_url: Some("https://tool.chio.example/mcp".to_string()),
            homepage_url: Some("https://tool.chio.example".to_string()),
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: "artifact-1".to_string(),
            source_artifact_sha256: "deadbeef".to_string(),
        },
        boundary: GenericListingBoundary::default(),
    }
}

fn signed_sample_listing(owner_id: &str, signing_keypair: &Keypair) -> SignedGenericListing {
    SignedGenericListing::sign(sample_listing(owner_id, signing_keypair), signing_keypair)
        .test_expect("sign sample listing")
}

fn sample_publisher(
    role: GenericRegistryPublisherRole,
    operator_id: &str,
) -> GenericRegistryPublisher {
    GenericRegistryPublisher {
        role,
        operator_id: operator_id.to_string(),
        operator_name: Some(format!("Operator {operator_id}")),
        registry_url: format!("https://{operator_id}.chio.example"),
        upstream_registry_urls: Vec::new(),
    }
}

fn sample_activation(listing: &SignedGenericListing) -> SignedGenericTrustActivation {
    let authority_keypair = Keypair::generate();
    let activation = build_generic_trust_activation_artifact(
        "origin-a",
        Some("Origin A".to_string()),
        &GenericTrustActivationIssueRequest {
            listing: listing.clone(),
            admission_class: GenericTrustAdmissionClass::Reviewable,
            disposition: GenericTrustActivationDisposition::Approved,
            eligibility: GenericTrustActivationEligibility {
                allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
                allowed_publisher_roles: vec![GenericRegistryPublisherRole::Origin],
                allowed_statuses: vec![GenericListingStatus::Active],
                require_fresh_listing: true,
                require_bond_backing: false,
                required_listing_operator_ids: vec!["origin-a".to_string()],
                policy_reference: Some("policy/open-registry/default".to_string()),
            },
            review_context: GenericTrustActivationReviewContext {
                publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
                freshness: GenericListingReplicaFreshness {
                    state: GenericListingFreshnessState::Fresh,
                    age_secs: 5,
                    max_age_secs: 300,
                    valid_until: 400,
                    generated_at: 100,
                },
            },
            requested_by: "ops@chio.example".to_string(),
            reviewed_by: Some("reviewer@chio.example".to_string()),
            requested_at: Some(120),
            reviewed_at: Some(121),
            expires_at: Some(500),
            note: Some("approved".to_string()),
        },
        121,
    )
    .test_expect("build activation");
    SignedGenericTrustActivation::sign(activation, &authority_keypair)
        .test_expect("sign activation")
}

#[test]
fn sha256_hex_helper_accepts_exact_uppercase_compatible_digest() {
    assert!(is_sha256_hex(&"a".repeat(64)));
    assert!(is_sha256_hex(&"A".repeat(64)));
    assert!(!is_sha256_hex(&"a".repeat(63)));
    assert!(!is_sha256_hex(&format!("{}g", "a".repeat(63))));
}

#[test]
fn governance_evidence_reference_rejects_invalid_sha256() {
    let reference = GenericGovernanceEvidenceReference {
        kind: GenericGovernanceEvidenceKind::External,
        reference_id: "external-report-1".to_string(),
        uri: None,
        sha256: Some("not-a-digest".to_string()),
    };

    let error = reference
        .validate("evidence")
        .test_expect_err("invalid evidence sha256 rejected");
    assert!(error.contains("evidence.sha256"));
}

fn sample_charter_request() -> GenericGovernanceCharterIssueRequest {
    GenericGovernanceCharterIssueRequest {
        authority_scope: GenericGovernanceAuthorityScope {
            namespace: "https://registry.chio.example".to_string(),
            allowed_listing_operator_ids: vec!["origin-a".to_string()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            policy_reference: Some("policy/governance/default".to_string()),
        },
        allowed_case_kinds: vec![
            GenericGovernanceCaseKind::Dispute,
            GenericGovernanceCaseKind::Freeze,
            GenericGovernanceCaseKind::Sanction,
            GenericGovernanceCaseKind::Appeal,
        ],
        escalation_operator_ids: vec!["network-audit.chio.example".to_string()],
        issued_by: "governance@chio.example".to_string(),
        issued_at: Some(130),
        expires_at: Some(800),
        note: Some("default governance charter".to_string()),
    }
}

fn sample_charter(
    local_operator_id: &str,
    authority_keypair: &Keypair,
) -> SignedGenericGovernanceCharter {
    SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            local_operator_id,
            Some(format!("Operator {local_operator_id}")),
            &sample_charter_request(),
            130,
        )
        .test_expect("build charter"),
        authority_keypair,
    )
    .test_expect("sign charter")
}

fn sample_case_issue_request(
    charter: SignedGenericGovernanceCharter,
    listing: SignedGenericListing,
    activation: Option<SignedGenericTrustActivation>,
) -> GenericGovernanceCaseIssueRequest {
    let evidence_kind = if activation.is_some() {
        GenericGovernanceEvidenceKind::TrustActivation
    } else {
        GenericGovernanceEvidenceKind::Listing
    };
    let reference_id = activation.as_ref().map_or_else(
        || listing.body.listing_id.clone(),
        |activation| activation.body.activation_id.clone(),
    );
    GenericGovernanceCaseIssueRequest {
        charter,
        listing,
        activation,
        kind: GenericGovernanceCaseKind::Freeze,
        state: GenericGovernanceCaseState::Enforced,
        subject_operator_id: Some("origin-a".to_string()),
        escalated_to_operator_ids: Vec::new(),
        evidence_refs: vec![GenericGovernanceEvidenceReference {
            kind: evidence_kind,
            reference_id,
            uri: None,
            sha256: None,
        }],
        appeal_of_case_id: None,
        supersedes_case_id: None,
        issued_by: "governance@chio.example".to_string(),
        opened_at: Some(140),
        updated_at: Some(140),
        expires_at: Some(500),
        note: Some("freeze".to_string()),
    }
}

#[test]
fn generic_governance_freeze_requires_activation() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let charter = SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &sample_charter_request(),
            130,
        )
        .test_expect("build charter"),
        &authority_keypair,
    )
    .test_expect("sign charter");
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact(
            "origin-a",
            &GenericGovernanceCaseIssueRequest {
                charter: charter.clone(),
                listing: listing.clone(),
                activation: None,
                kind: GenericGovernanceCaseKind::Freeze,
                state: GenericGovernanceCaseState::Enforced,
                subject_operator_id: Some("origin-a".to_string()),
                escalated_to_operator_ids: Vec::new(),
                evidence_refs: vec![GenericGovernanceEvidenceReference {
                    kind: GenericGovernanceEvidenceKind::Listing,
                    reference_id: listing.body.listing_id.clone(),
                    uri: None,
                    sha256: None,
                }],
                appeal_of_case_id: None,
                supersedes_case_id: None,
                issued_by: "governance@chio.example".to_string(),
                opened_at: Some(140),
                updated_at: Some(140),
                expires_at: Some(500),
                note: Some("freeze".to_string()),
            },
            140,
        )
        .test_expect("build case"),
        &authority_keypair,
    )
    .test_expect("sign case");

    let evaluation = evaluate_generic_governance_case(
        &GenericGovernanceCaseEvaluationRequest {
            listing,
            current_publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
            activation: None,
            charter,
            case,
            prior_case: None,
            evaluated_at: Some(150),
        },
        150,
    )
    .test_expect("evaluate governance");
    assert!(!evaluation.blocks_admission);
    assert_eq!(
        evaluation.findings[0].code,
        GenericGovernanceFindingCode::MissingActivation
    );
}

#[test]
fn generic_governance_enforced_freeze_blocks_admission() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let activation = sample_activation(&listing);
    let charter = SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &sample_charter_request(),
            130,
        )
        .test_expect("build charter"),
        &authority_keypair,
    )
    .test_expect("sign charter");
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact(
            "origin-a",
            &GenericGovernanceCaseIssueRequest {
                charter: charter.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                kind: GenericGovernanceCaseKind::Freeze,
                state: GenericGovernanceCaseState::Enforced,
                subject_operator_id: Some("origin-a".to_string()),
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
                opened_at: Some(140),
                updated_at: Some(140),
                expires_at: Some(500),
                note: Some("freeze".to_string()),
            },
            140,
        )
        .test_expect("build case"),
        &authority_keypair,
    )
    .test_expect("sign case");

    let evaluation = evaluate_generic_governance_case(
        &GenericGovernanceCaseEvaluationRequest {
            listing,
            current_publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
            activation: Some(activation),
            charter,
            case,
            prior_case: None,
            evaluated_at: Some(150),
        },
        150,
    )
    .test_expect("evaluate governance");
    assert!(evaluation.findings.is_empty());
    assert!(evaluation.blocks_admission);
    assert_eq!(
        evaluation.effective_state,
        GenericGovernanceEffectiveState::Frozen
    );
}

#[test]
fn generic_governance_case_issue_rejects_non_local_activation_authority() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let activation = sample_activation(&listing);
    let mut forged_activation_body = activation.body.clone();
    forged_activation_body.local_operator_id = "remote-b".to_string();
    forged_activation_body.local_operator_name = Some("Remote B".to_string());
    let forged_activation =
        SignedGenericTrustActivation::sign(forged_activation_body, &Keypair::generate())
            .test_expect("sign forged activation");
    let charter = SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &sample_charter_request(),
            130,
        )
        .test_expect("build charter"),
        &authority_keypair,
    )
    .test_expect("sign charter");

    let error = build_generic_governance_case_artifact(
        "origin-a",
        &GenericGovernanceCaseIssueRequest {
            charter,
            listing,
            activation: Some(forged_activation),
            kind: GenericGovernanceCaseKind::Freeze,
            state: GenericGovernanceCaseState::Enforced,
            subject_operator_id: Some("origin-a".to_string()),
            escalated_to_operator_ids: Vec::new(),
            evidence_refs: vec![GenericGovernanceEvidenceReference {
                kind: GenericGovernanceEvidenceKind::TrustActivation,
                reference_id: activation.body.activation_id,
                uri: None,
                sha256: None,
            }],
            appeal_of_case_id: None,
            supersedes_case_id: None,
            issued_by: "governance@chio.example".to_string(),
            opened_at: Some(140),
            updated_at: Some(140),
            expires_at: Some(500),
            note: Some("freeze".to_string()),
        },
        140,
    )
    .test_expect_err("non-local activation authority rejected");
    assert!(error.contains("issued by the governing operator"));
}

#[test]
fn generic_governance_evaluation_rejects_non_local_activation_authority() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let activation = sample_activation(&listing);
    let charter = SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &sample_charter_request(),
            130,
        )
        .test_expect("build charter"),
        &authority_keypair,
    )
    .test_expect("sign charter");
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact(
            "origin-a",
            &GenericGovernanceCaseIssueRequest {
                charter: charter.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                kind: GenericGovernanceCaseKind::Freeze,
                state: GenericGovernanceCaseState::Enforced,
                subject_operator_id: Some("origin-a".to_string()),
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
                opened_at: Some(140),
                updated_at: Some(140),
                expires_at: Some(500),
                note: Some("freeze".to_string()),
            },
            140,
        )
        .test_expect("build case"),
        &authority_keypair,
    )
    .test_expect("sign case");
    let mut forged_activation_body = activation.body.clone();
    forged_activation_body.local_operator_id = "remote-b".to_string();
    forged_activation_body.local_operator_name = Some("Remote B".to_string());
    let forged_activation =
        SignedGenericTrustActivation::sign(forged_activation_body, &Keypair::generate())
            .test_expect("sign forged activation");

    let evaluation = evaluate_generic_governance_case(
        &GenericGovernanceCaseEvaluationRequest {
            listing,
            current_publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
            activation: Some(forged_activation),
            charter,
            case,
            prior_case: None,
            evaluated_at: Some(150),
        },
        150,
    )
    .test_expect("evaluate governance");
    assert!(!evaluation.blocks_admission);
    assert_eq!(
        evaluation.findings[0].code,
        GenericGovernanceFindingCode::ActivationMismatch
    );
}

#[test]
fn generic_governance_charter_scope_mismatch_fails_closed() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let activation = sample_activation(&listing);
    let charter = SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &sample_charter_request(),
            130,
        )
        .test_expect("build charter"),
        &authority_keypair,
    )
    .test_expect("sign charter");
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact(
            "origin-a",
            &GenericGovernanceCaseIssueRequest {
                charter: charter.clone(),
                listing: listing.clone(),
                activation: Some(activation.clone()),
                kind: GenericGovernanceCaseKind::Sanction,
                state: GenericGovernanceCaseState::Enforced,
                subject_operator_id: Some("origin-a".to_string()),
                escalated_to_operator_ids: Vec::new(),
                evidence_refs: vec![GenericGovernanceEvidenceReference {
                    kind: GenericGovernanceEvidenceKind::External,
                    reference_id: "incident-1".to_string(),
                    uri: None,
                    sha256: None,
                }],
                appeal_of_case_id: None,
                supersedes_case_id: None,
                issued_by: "governance@chio.example".to_string(),
                opened_at: Some(140),
                updated_at: Some(140),
                expires_at: Some(500),
                note: Some("sanction".to_string()),
            },
            140,
        )
        .test_expect("build case"),
        &authority_keypair,
    )
    .test_expect("sign case");

    let evaluation = evaluate_generic_governance_case(
        &GenericGovernanceCaseEvaluationRequest {
            listing,
            current_publisher: sample_publisher(
                GenericRegistryPublisherRole::Origin,
                "other-origin",
            ),
            activation: Some(activation),
            charter,
            case,
            prior_case: None,
            evaluated_at: Some(150),
        },
        150,
    )
    .test_expect("evaluate governance");
    assert_eq!(
        evaluation.findings[0].code,
        GenericGovernanceFindingCode::CharterScopeMismatch
    );
}

#[test]
fn generic_governance_appeal_requires_prior_case() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let activation = sample_activation(&listing);
    let charter = SignedGenericGovernanceCharter::sign(
        build_generic_governance_charter_artifact(
            "origin-a",
            Some("Origin A".to_string()),
            &sample_charter_request(),
            130,
        )
        .test_expect("build charter"),
        &authority_keypair,
    )
    .test_expect("sign charter");
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact(
            "origin-a",
            &GenericGovernanceCaseIssueRequest {
                charter: charter.clone(),
                listing: listing.clone(),
                activation: Some(activation),
                kind: GenericGovernanceCaseKind::Appeal,
                state: GenericGovernanceCaseState::Open,
                subject_operator_id: Some("origin-a".to_string()),
                escalated_to_operator_ids: Vec::new(),
                evidence_refs: vec![GenericGovernanceEvidenceReference {
                    kind: GenericGovernanceEvidenceKind::External,
                    reference_id: "appeal-1".to_string(),
                    uri: None,
                    sha256: None,
                }],
                appeal_of_case_id: Some("case-missing".to_string()),
                supersedes_case_id: None,
                issued_by: "governance@chio.example".to_string(),
                opened_at: Some(140),
                updated_at: Some(140),
                expires_at: Some(500),
                note: Some("appeal".to_string()),
            },
            140,
        )
        .test_expect("build case"),
        &authority_keypair,
    )
    .test_expect("sign case");

    let evaluation = evaluate_generic_governance_case(
        &GenericGovernanceCaseEvaluationRequest {
            listing,
            current_publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
            activation: None,
            charter,
            case,
            prior_case: None,
            evaluated_at: Some(150),
        },
        150,
    )
    .test_expect("evaluate governance");
    assert_eq!(
        evaluation.findings[0].code,
        GenericGovernanceFindingCode::AppealTargetMissing
    );
}

#[test]
fn generic_governance_authority_scope_rejects_blank_operator_ids() {
    let error = GenericGovernanceAuthorityScope {
        namespace: "https://registry.chio.example".to_string(),
        allowed_listing_operator_ids: vec!["   ".to_string()],
        allowed_actor_kinds: Vec::new(),
        policy_reference: None,
    }
    .validate()
    .test_expect_err("blank operator ids rejected");

    assert!(error.contains("authority_scope.allowed_listing_operator_ids[0]"));
}

#[test]
fn generic_governance_charter_validate_rejects_expired_artifact() {
    let error = GenericGovernanceCharterArtifact {
        schema: GENERIC_GOVERNANCE_CHARTER_ARTIFACT_SCHEMA.to_string(),
        charter_id: "charter-1".to_string(),
        governing_operator_id: "origin-a".to_string(),
        governing_operator_name: Some("Origin A".to_string()),
        authority_scope: GenericGovernanceAuthorityScope {
            namespace: "https://registry.chio.example".to_string(),
            allowed_listing_operator_ids: vec!["origin-a".to_string()],
            allowed_actor_kinds: vec![GenericListingActorKind::ToolServer],
            policy_reference: None,
        },
        allowed_case_kinds: vec![GenericGovernanceCaseKind::Freeze],
        escalation_operator_ids: vec!["network-audit.chio.example".to_string()],
        issued_at: 200,
        expires_at: Some(199),
        issued_by: "governance@chio.example".to_string(),
        note: None,
    }
    .validate()
    .test_expect_err("expired charters rejected");

    assert!(error.contains("expires_at must be greater than issued_at"));
}

#[test]
fn generic_governance_case_validate_requires_escalation_targets() {
    let error = GenericGovernanceCaseArtifact {
        schema: GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA.to_string(),
        case_id: "case-1".to_string(),
        charter_id: "charter-1".to_string(),
        governing_operator_id: "origin-a".to_string(),
        kind: GenericGovernanceCaseKind::Freeze,
        state: GenericGovernanceCaseState::Escalated,
        namespace: "https://registry.chio.example".to_string(),
        listing_id: "listing-1".to_string(),
        activation_id: Some("activation-1".to_string()),
        subject_operator_id: Some("origin-a".to_string()),
        opened_at: 100,
        updated_at: 100,
        expires_at: Some(200),
        escalated_to_operator_ids: Vec::new(),
        evidence_refs: vec![GenericGovernanceEvidenceReference {
            kind: GenericGovernanceEvidenceKind::External,
            reference_id: "incident-1".to_string(),
            uri: None,
            sha256: None,
        }],
        appeal_of_case_id: None,
        supersedes_case_id: None,
        issued_by: "governance@chio.example".to_string(),
        note: None,
    }
    .validate()
    .test_expect_err("escalated cases require operator targets");

    assert!(error.contains("escalated case requires escalated_to_operator_ids"));
}

#[test]
fn generic_governance_case_validate_rejects_appeal_id_on_non_appeal_case() {
    let error = GenericGovernanceCaseArtifact {
        schema: GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA.to_string(),
        case_id: "case-1".to_string(),
        charter_id: "charter-1".to_string(),
        governing_operator_id: "origin-a".to_string(),
        kind: GenericGovernanceCaseKind::Sanction,
        state: GenericGovernanceCaseState::Open,
        namespace: "https://registry.chio.example".to_string(),
        listing_id: "listing-1".to_string(),
        activation_id: None,
        subject_operator_id: Some("origin-a".to_string()),
        opened_at: 100,
        updated_at: 100,
        expires_at: Some(200),
        escalated_to_operator_ids: Vec::new(),
        evidence_refs: vec![GenericGovernanceEvidenceReference {
            kind: GenericGovernanceEvidenceKind::External,
            reference_id: "incident-1".to_string(),
            uri: None,
            sha256: None,
        }],
        appeal_of_case_id: Some("case-0".to_string()),
        supersedes_case_id: None,
        issued_by: "governance@chio.example".to_string(),
        note: None,
    }
    .validate()
    .test_expect_err("appeal target only valid for appeal cases");

    assert!(error.contains("only valid for appeal cases"));
}

#[test]
fn generic_governance_case_issue_request_rejects_invalid_listing_signature() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let charter = sample_charter("origin-a", &authority_keypair);
    let mut tampered_listing = listing.clone();
    tampered_listing.body.subject.actor_id = "tool-server-b".to_string();

    let error = sample_case_issue_request(charter, tampered_listing, None)
        .validate()
        .test_expect_err("tampered listing signature rejected");

    assert!(error.contains("listing signature is invalid"));
}

#[test]
fn generic_governance_case_issue_request_rejects_invalid_activation_signature() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let charter = sample_charter("origin-a", &authority_keypair);
    let activation = sample_activation(&listing);
    let mut tampered_activation = activation.clone();
    tampered_activation.body.local_operator_id = "remote-b".to_string();

    let error = sample_case_issue_request(charter, listing, Some(tampered_activation))
        .validate()
        .test_expect_err("tampered activation signature rejected");

    assert!(error.contains("trust activation signature is invalid"));
}

#[test]
fn build_generic_governance_charter_artifact_uses_request_issued_at() {
    let mut request = sample_charter_request();
    request.issued_at = Some(777);

    let charter = build_generic_governance_charter_artifact(
        "origin-a",
        Some("Origin A".to_string()),
        &request,
        130,
    )
    .test_expect("build charter");

    assert_eq!(charter.issued_at, 777);
    assert_eq!(charter.governing_operator_id, "origin-a");
    assert!(charter.charter_id.starts_with("charter-"));
}

#[test]
fn generic_governance_evaluation_rejects_invalid_case_signature() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let activation = sample_activation(&listing);
    let charter = sample_charter("origin-a", &authority_keypair);
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact(
            "origin-a",
            &sample_case_issue_request(charter.clone(), listing.clone(), Some(activation.clone())),
            140,
        )
        .test_expect("build case"),
        &authority_keypair,
    )
    .test_expect("sign case");
    let mut tampered_case = case.clone();
    tampered_case.body.note = Some("tampered".to_string());

    let evaluation = evaluate_generic_governance_case(
        &GenericGovernanceCaseEvaluationRequest {
            listing,
            current_publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
            activation: Some(activation),
            charter,
            case: tampered_case,
            prior_case: None,
            evaluated_at: Some(150),
        },
        150,
    )
    .test_expect("evaluate governance");

    assert_eq!(
        evaluation.findings[0].code,
        GenericGovernanceFindingCode::CaseUnverifiable
    );
}

#[test]
fn generic_governance_supersession_target_mismatch_fails_closed() {
    let listing_keypair = Keypair::generate();
    let authority_keypair = Keypair::generate();
    let listing = signed_sample_listing("origin-a", &listing_keypair);
    let activation = sample_activation(&listing);
    let charter = sample_charter("origin-a", &authority_keypair);
    let mut case_request =
        sample_case_issue_request(charter.clone(), listing.clone(), Some(activation.clone()));
    case_request.kind = GenericGovernanceCaseKind::Sanction;
    case_request.supersedes_case_id = Some("prior-case-1".to_string());
    case_request.evidence_refs[0].kind = GenericGovernanceEvidenceKind::External;
    case_request.evidence_refs[0].reference_id = "incident-1".to_string();
    let case = SignedGenericGovernanceCase::sign(
        build_generic_governance_case_artifact("origin-a", &case_request, 140)
            .test_expect("build case"),
        &authority_keypair,
    )
    .test_expect("sign case");
    let prior_case = SignedGenericGovernanceCase::sign(
        GenericGovernanceCaseArtifact {
            schema: GENERIC_GOVERNANCE_CASE_ARTIFACT_SCHEMA.to_string(),
            case_id: "prior-case-1".to_string(),
            charter_id: charter.body.charter_id.clone(),
            governing_operator_id: "origin-a".to_string(),
            kind: GenericGovernanceCaseKind::Freeze,
            state: GenericGovernanceCaseState::Resolved,
            namespace: "https://registry.chio.example".to_string(),
            listing_id: "different-listing".to_string(),
            activation_id: Some(activation.body.activation_id.clone()),
            subject_operator_id: Some("origin-a".to_string()),
            opened_at: 120,
            updated_at: 121,
            expires_at: Some(500),
            escalated_to_operator_ids: Vec::new(),
            evidence_refs: vec![GenericGovernanceEvidenceReference {
                kind: GenericGovernanceEvidenceKind::External,
                reference_id: "prior-incident".to_string(),
                uri: None,
                sha256: None,
            }],
            appeal_of_case_id: None,
            supersedes_case_id: None,
            issued_by: "governance@chio.example".to_string(),
            note: None,
        },
        &authority_keypair,
    )
    .test_expect("sign prior case");

    let evaluation = evaluate_generic_governance_case(
        &GenericGovernanceCaseEvaluationRequest {
            listing,
            current_publisher: sample_publisher(GenericRegistryPublisherRole::Origin, "origin-a"),
            activation: Some(activation),
            charter,
            case,
            prior_case: Some(prior_case),
            evaluated_at: Some(150),
        },
        150,
    )
    .test_expect("evaluate governance");

    assert_eq!(
        evaluation.findings[0].code,
        GenericGovernanceFindingCode::SupersessionTargetInvalid
    );
}

#[test]
fn capability_lease_validates_signature_lifetime_and_scope() {
    let issuer = Keypair::from_seed(&[11u8; 32]);
    let lease = CapabilityLeaseArtifact {
        schema: CAPABILITY_LEASE_SCHEMA_V1.to_string(),
        lease_id: "lease:buyer:refund:001".to_string(),
        issuer: "did:chio:buyer".to_string(),
        subject: "did:chio:vendor-payments".to_string(),
        scope_digest: "a".repeat(64),
        action_class: CapabilityLeaseActionClass::NarrowDestructive,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
    };
    let signed = SignedCapabilityLease::sign(lease, &issuer).test_expect("sign lease");

    assert!(matches!(
        verify_capability_lease(&signed, 999, Some("a".repeat(64))),
        Err(GovernanceAuthorizationError::LeaseNotYetValid(_))
    ));
    assert!(verify_capability_lease(&signed, 1_500, Some("a".repeat(64))).is_ok());
    assert!(matches!(
        verify_capability_lease(&signed, 2_000, Some("a".repeat(64))),
        Err(GovernanceAuthorizationError::LeaseExpiredOrUnknown(_))
    ));
    assert!(matches!(
        verify_capability_lease(&signed, 1_500, Some("b".repeat(64))),
        Err(GovernanceAuthorizationError::ScopeDigestMismatch)
    ));
}

#[test]
fn destructive_governance_receipt_binds_lease_workflow_and_step_hash() {
    let issuer = Keypair::from_seed(&[12u8; 32]);
    let receipt = GovernanceReceiptArtifact {
        schema: GOVERNANCE_RECEIPT_SCHEMA_V1.to_string(),
        receipt_id: "gov:buyer:refund:001".to_string(),
        authorizing_kernel: "did:chio:buyer".to_string(),
        case_kind: GovernanceReceiptCaseKind::DestructiveAuthorization,
        authorized_lease_id: "lease:buyer:refund:001".to_string(),
        workflow_id: "wf-chio-refund-001".to_string(),
        step_sha256: "c".repeat(64),
        issued_at_unix_ms: 1_100,
        expires_at_unix_ms: 1_900,
    };
    let signed =
        SignedGovernanceReceipt::sign(receipt, &issuer).test_expect("sign governance receipt");

    assert!(verify_destructive_authorization(
        &signed,
        "lease:buyer:refund:001",
        "wf-chio-refund-001",
        &"c".repeat(64),
        1_500,
    )
    .is_ok());
    assert!(matches!(
        verify_destructive_authorization(
            &signed,
            "lease:buyer:refund:001",
            "wf-chio-refund-001",
            &"c".repeat(64),
            1_099,
        ),
        Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
            _
        ))
    ));
    assert!(matches!(
        verify_step_governance_boundary(true, Some(&signed), 1_099),
        Err(GovernanceAuthorizationError::GovernanceReceiptNotYetValid(
            _
        ))
    ));
    assert!(matches!(
        verify_destructive_authorization(
            &signed,
            "lease:buyer:refund:001",
            "wf-other",
            &"c".repeat(64),
            1_500,
        ),
        Err(GovernanceAuthorizationError::WorkflowMismatch)
    ));
}

#[test]
fn non_destructive_steps_do_not_require_governance_receipts() {
    assert!(verify_step_governance_boundary(false, None, 1_500).is_ok());
    assert!(matches!(
        verify_step_governance_boundary(true, None, 1_500),
        Err(GovernanceAuthorizationError::GovernanceReceiptRequired)
    ));
}
