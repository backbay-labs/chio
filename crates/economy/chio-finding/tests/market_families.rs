//! Behavioral coverage for the market artifact families: happy-path
//! construction and signing per family, then the adversarial rejections
//! the wire types must enforce on their own (surface obligations such as
//! liveness, store exclusivity, and cross-artifact digest resolution are
//! covered at their owning surfaces).

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_admission_id, compute_allocation_id, compute_authorization_id, compute_profile_id,
    compute_report_id, compute_terms_id, signed_envelope_sha256, verify_signed_admission,
    verify_signed_bond_backing, verify_signed_market_terms, verify_signed_seller_authorization,
    verify_signed_verifier_report, FindingAdmission, FindingAuthorityKeyPolicy,
    FindingBackingRequirement, FindingBbsIssuerPolicy, FindingBondBacking, FindingBondClass,
    FindingChallengeBondLimit, FindingChallengeVerifierProfile, FindingCheckpointLogPolicy,
    FindingClaimedVerdict, FindingCollateralVault, FindingError, FindingFacetKind,
    FindingFacetOutcome, FindingFacetResult, FindingFeeEvent, FindingFeeTerminalBinding,
    FindingGuaranteeClass, FindingMarketTerms, FindingOutcomeClass, FindingPayee,
    FindingPoolBinding, FindingPreRunTemplate, FindingPredicate, FindingReceiptRole,
    FindingReceiptSignerRole, FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind,
    FindingReplayRecipeInput, FindingResourceCaps, FindingSellerAuthorization,
    FindingVerifierReport, FINDING_ADMISSION_SCHEMA_V1, FINDING_BOND_BACKING_SCHEMA_V1,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_MARKET_TERMS_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SELLER_AUTHORIZATION_SCHEMA_V1,
    FINDING_VERIFIER_REPORT_SCHEMA_V1, MAX_FINDING_ARTIFACT_ITEMS, MAX_FINDING_IDENTIFIER_BYTES,
    MAX_FINDING_TEXT_BYTES,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn key_policy(seed: u8, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn resource_caps() -> FindingResourceCaps {
    FindingResourceCaps {
        max_recipe_bytes: 262_144,
        max_evidence_receipts: 64,
        max_runtime_secs: 900,
        max_memory_bytes: 2_147_483_648,
    }
}

fn profile_body() -> Result<FindingChallengeVerifierProfile, FindingError> {
    let mut profile = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_string(),
        profile_id: String::new(),
        governance_authority: keypair(1).public_key(),
        operator: "venue-operator".to_string(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: key_policy(11, "production"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: key_policy(12, "delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: key_policy(13, "replay"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id: "local-log-wedge".to_string(),
            signer: key_policy(14, "checkpoint"),
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "bbs-issuer-fp".to_string(),
            key_hex: HEX64.to_string(),
            registry_ref: "registry/bbs-issuers".to_string(),
            key_epoch: 1,
            valid_from: 1_700_000_000,
            valid_until: 1_900_000_000,
            revocation_status_ref: "revocations/bbs".to_string(),
        },
        allowed_runner_manifests: vec![HEX64.to_string()],
        required_receipt_semantics: "chio.mediated_spend.v1".to_string(),
        resolver_policy_ref: "resolver-policy-v1".to_string(),
        retention_policy_ref: "retention-forever-v1".to_string(),
        resource_caps: resource_caps(),
        predicate_engine: "chio-replay-v1".to_string(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::BondBacking,
            FindingFacetKind::GuaranteeConsistency,
        ],
        verifier_report_signer: key_policy(15, "verifier-report"),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    profile.profile_id = (compute_profile_id(&profile))?;
    Ok(profile)
}

fn terms_body(seller: &Keypair) -> Result<FindingMarketTerms, FindingError> {
    let mut terms = FindingMarketTerms {
        schema: FINDING_MARKET_TERMS_SCHEMA_V1.to_string(),
        terms_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        seller: seller.public_key(),
        backing_requirement: FindingBackingRequirement {
            base_finding_stake: MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            },
            maximum_sale_exposure: MonetaryAmount {
                units: 450,
                currency: "USD".to_string(),
            },
            collateral_policy: "venue_ledger_exclusive_v1".to_string(),
        },
        filing_window_secs: 86_400,
        claim_window_secs: 604_800,
        appeal_window_secs: 259_200,
        audit_epoch_length_secs: 2_592_000,
        audit_eligible: true,
        decision_rule_refs: vec!["decision/replay-v1".to_string()],
        verifier_profile_envelope_sha256: HEX64.to_string(),
        challenge_bond_limits: vec![FindingChallengeBondLimit {
            guarantee_class: FindingGuaranteeClass::DeterministicReplay,
            min_bond: MonetaryAmount {
                units: 10,
                currency: "USD".to_string(),
            },
            max_bond: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
        }],
        payout_policy: "pro_rata_capped_v1".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    terms.terms_id = (compute_terms_id(&terms))?;
    Ok(terms)
}

fn authorization_body(
    issuer: &Keypair,
    seller: &Keypair,
) -> Result<FindingSellerAuthorization, FindingError> {
    let mut authorization = FindingSellerAuthorization {
        schema: FINDING_SELLER_AUTHORIZATION_SCHEMA_V1.to_string(),
        authorization_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        issuer: issuer.public_key(),
        seller: seller.public_key(),
        provider_server_id: "finding-server".to_string(),
        provider_tool: "finding.reveal".to_string(),
        payee: FindingPayee::Beneficiary {
            destination: "rail:venue-ledger:seller-42".to_string(),
            currency: "USD".to_string(),
        },
        revocation_status_ref: "revocations/seller-auth".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    authorization.authorization_id = (compute_authorization_id(&authorization))?;
    Ok(authorization)
}
fn backing_body(authority: &Keypair, seller: &Keypair) -> Result<FindingBondBacking, FindingError> {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: authority.public_key(),
        seller: seller.public_key(),
        authorization_envelope_sha256: HEX64.to_string(),
        finding_id: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        terms_envelope_sha256: HEX64.to_string(),
        profile_envelope_sha256: HEX64.to_string(),
        fee_requirement_sha256: HEX64.to_string(),
        fee_schedule_envelope_sha256: HEX64.to_string(),
        bond_class: FindingBondClass::Listing,
        locked_amount: MonetaryAmount {
            units: 500,
            currency: "USD".to_string(),
        },
        maximum_sale_exposure: MonetaryAmount {
            units: 450,
            currency: "USD".to_string(),
        },
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: "vault:finding-collateral".to_string(),
            operator_epoch: 1,
        },
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    backing.allocation_id = (compute_allocation_id(&backing))?;
    Ok(backing)
}
fn verified_facets() -> Vec<FindingFacetResult> {
    FindingFacetKind::ALL
        .into_iter()
        .map(|facet| {
            let outcome = match facet {
                FindingFacetKind::StatusLiveness => FindingFacetOutcome::Unavailable,
                _ => FindingFacetOutcome::Verified,
            };
            FindingFacetResult {
                facet,
                outcome,
                reason: "evaluated under the pinned verifier profile".to_string(),
                evidence_refs: Vec::new(),
            }
        })
        .collect()
}
fn report_body(verifier: &Keypair) -> Result<FindingVerifierReport, FindingError> {
    let mut report = FindingVerifierReport {
        schema: FINDING_VERIFIER_REPORT_SCHEMA_V1.to_string(),
        report_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        verifier_profile_id: HEX64.to_string(),
        verifier_profile_envelope_sha256: HEX64.to_string(),
        verifier_implementation_id: "chio-finding-verifier/0.1".to_string(),
        resolved_evidence_bundle_sha256: HEX64.to_string(),
        trust_root_snapshot_sha256: HEX64.to_string(),
        resolver_policy_sha256: HEX64.to_string(),
        trusted_time_input_sha256: HEX64.to_string(),
        facets: verified_facets(),
        backing_allocation_id: Some(HEX64.to_string()),
        verifier_authority: verifier.public_key(),
        verifier_key_epoch: 1,
        evaluation_time: 1_750_000_000,
    };
    report.report_id = (compute_report_id(&report))?;
    Ok(report)
}
fn admission_body(venue: &Keypair) -> Result<FindingAdmission, FindingError> {
    let mut admission = FindingAdmission {
        schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
        admission_id: String::new(),
        venue: venue.public_key(),
        venue_id: "venue-wedge".to_string(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        seller_authorization_envelope_sha256: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        listing_envelope_sha256: HEX64.to_string(),
        server_id: "finding-server".to_string(),
        metadata_url: format!("https://venue.example/v1/findings/{HEX64}"),
        pricing_hint_envelope_sha256: HEX64.to_string(),
        capability_scope: format!("finding:{HEX64}"),
        publisher_operator_id: "venue-operator".to_string(),
        payee_destination: "rail:venue-ledger:seller-42".to_string(),
        fee_schedule_envelope_sha256: HEX64.to_string(),
        verifier_report_id: HEX64.to_string(),
        verifier_report_envelope_sha256: HEX64.to_string(),
        terms_envelope_sha256: HEX64.to_string(),
        profile_envelope_sha256: HEX64.to_string(),
        fee_terminals: vec![
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: HEX64.to_string(),
                event: FindingFeeEvent::Publication,
                payer: "seller-42".to_string(),
                amount: MonetaryAmount {
                    units: 5,
                    currency: "USD".to_string(),
                },
                pool_principal_id: "pool:audit".to_string(),
                rail_destination: "rail:venue-ledger:audit-pool".to_string(),
                instruction_sha256: HEX64.to_string(),
                observation_sha256: HEX64.to_string(),
            },
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: HEX64.to_string(),
                event: FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                payer: "seller-42".to_string(),
                amount: MonetaryAmount {
                    units: 3,
                    currency: "USD".to_string(),
                },
                pool_principal_id: "pool:audit".to_string(),
                rail_destination: "rail:venue-ledger:audit-pool".to_string(),
                instruction_sha256: HEX64.to_string(),
                observation_sha256: HEX64.to_string(),
            },
        ],
        backing_allocation_id: HEX64.to_string(),
        backing_envelope_sha256: HEX64.to_string(),
        audit_pool: FindingPoolBinding {
            principal_id: "pool:audit".to_string(),
            rail_destination: "rail:venue-ledger:audit-pool".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolBinding {
            principal_id: "pool:challenge-admin".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
        status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: 1_700_000_000,
        expires_at: 1_800_000_000,
    };
    admission.admission_id = (compute_admission_id(&admission))?;
    Ok(admission)
}
fn recipe_environment() -> FindingRecipeEnvironment {
    FindingRecipeEnvironment {
        runtime_image_sha256: HEX64.to_string(),
        platform: "linux/amd64".to_string(),
        network_policy: "deny_all".to_string(),
        clock_policy: "fixed:1700000000".to_string(),
        randomness_policy: "seed:42".to_string(),
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
    }
}
fn recipe_body() -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: HEX64.to_string(),
        context_sha256: HEX64.to_string(),
        payload_sha256: HEX64.to_string(),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: HEX64.to_string(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: HEX64.to_string(),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: HEX64.to_string(),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: HEX64.to_string(),
        environment: recipe_environment(),
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: HEX64.to_string(),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}
#[test]
fn every_family_validates_and_verifies_under_its_pinned_authority() -> TestResult {
    let governance = keypair(1);
    let seller = keypair(2);
    let issuer = keypair(3);
    let collateral = keypair(4);
    let verifier = keypair(15);
    let venue = keypair(6);
    let profile = profile_body()?;
    (profile.validate())?;
    let signed_profile = (SignedExportEnvelope::sign(profile, &governance))?;
    (chio_finding::verify_signed_profile(&signed_profile, &governance.public_key()))?;
    assert!(!(signed_envelope_sha256(&signed_profile))?.is_empty());

    let terms = terms_body(&seller)?;
    let signed_terms = (SignedExportEnvelope::sign(terms, &seller))?;
    (verify_signed_market_terms(&signed_terms))?;

    let authorization = authorization_body(&issuer, &seller)?;
    let signed_authorization = (SignedExportEnvelope::sign(authorization, &issuer))?;
    (verify_signed_seller_authorization(&signed_authorization))?;

    let backing = backing_body(&collateral, &seller)?;
    let signed_backing = (SignedExportEnvelope::sign(backing, &collateral))?;
    (verify_signed_bond_backing(&signed_backing, &collateral.public_key()))?;

    let report = report_body(&verifier)?;
    let signed_report = (SignedExportEnvelope::sign(report, &verifier))?;
    (verify_signed_verifier_report(&signed_report, &verifier.public_key()))?;

    let admission = admission_body(&venue)?;
    let signed_admission = (SignedExportEnvelope::sign(admission, &venue))?;
    (verify_signed_admission(&signed_admission, &venue.public_key(), "venue-wedge"))?;

    let recipe = recipe_body();
    (recipe.validate())?;
    assert_eq!((recipe.canonical_sha256())?.len(), 64);
    Ok(())
}
#[test]
fn envelope_signed_by_another_key_is_rejected_for_every_family() -> TestResult {
    let seller = keypair(2);
    let issuer = keypair(3);
    let collateral = keypair(4);
    let verifier = keypair(15);
    let venue = keypair(6);
    let interloper = keypair(9);
    let signed_terms = (SignedExportEnvelope::sign(terms_body(&seller)?, &interloper))?;
    assert_eq!(
        verify_signed_market_terms(&signed_terms),
        Err(FindingError::AuthorityMismatch("market_terms"))
    );
    let signed_authorization =
        (SignedExportEnvelope::sign(authorization_body(&issuer, &seller)?, &interloper))?;
    assert_eq!(
        verify_signed_seller_authorization(&signed_authorization),
        Err(FindingError::AuthorityMismatch("seller_authorization"))
    );
    let signed_backing =
        (SignedExportEnvelope::sign(backing_body(&collateral, &seller)?, &interloper))?;
    assert_eq!(
        verify_signed_bond_backing(&signed_backing, &collateral.public_key()),
        Err(FindingError::AuthorityMismatch("bond_backing"))
    );
    let signed_report = (SignedExportEnvelope::sign(report_body(&verifier)?, &interloper))?;
    assert_eq!(
        verify_signed_verifier_report(&signed_report, &verifier.public_key()),
        Err(FindingError::AuthorityMismatch("verifier_report"))
    );
    let signed_admission = (SignedExportEnvelope::sign(admission_body(&venue)?, &interloper))?;
    assert_eq!(
        verify_signed_admission(&signed_admission, &venue.public_key(), "venue-wedge"),
        Err(FindingError::AuthorityMismatch("admission"))
    );
    Ok(())
}

#[test]
fn profile_body_authority_must_match_the_governance_pin() -> TestResult {
    let governance = keypair(1);
    let interloper = keypair(9);
    let mut profile = profile_body()?;
    profile.governance_authority = interloper.public_key();
    profile.profile_id = compute_profile_id(&profile)?;
    let signed = SignedExportEnvelope::sign(profile, &governance)?;

    assert_eq!(
        chio_finding::verify_signed_profile(&signed, &governance.public_key()),
        Err(FindingError::AuthorityMismatch("profile"))
    );
    Ok(())
}

#[test]
fn tampered_bodies_fail_their_content_addressed_ids() -> TestResult {
    let seller = keypair(2);
    let venue = keypair(6);

    let mut profile = profile_body()?;
    profile.operator = "someone-else".to_string();
    assert_eq!(
        profile.validate(),
        Err(FindingError::ArtifactIdMismatch("profile_id"))
    );

    let mut terms = terms_body(&seller)?;
    terms.backing_requirement.maximum_sale_exposure.units += 1;
    assert_eq!(
        terms.validate(),
        Err(FindingError::ArtifactIdMismatch("terms_id"))
    );

    let mut admission = admission_body(&venue)?;
    admission.payee_destination = "rail:venue-ledger:attacker".to_string();
    assert_eq!(
        admission.validate(),
        Err(FindingError::ArtifactIdMismatch("admission_id"))
    );
    Ok(())
}

#[test]
fn profile_requires_all_three_receipt_roles_exactly_once() -> TestResult {
    let mut profile = profile_body()?;
    profile.receipt_signers.pop();
    profile.profile_id = (compute_profile_id(&profile))?;
    assert_eq!(
        profile.validate(),
        Err(FindingError::MissingEntry("receipt_signers[].role"))
    );

    let mut profile = profile_body()?;
    let duplicate = profile.receipt_signers[0].clone();
    profile.receipt_signers.push(duplicate);
    profile.profile_id = (compute_profile_id(&profile))?;
    assert_eq!(
        profile.validate(),
        Err(FindingError::DuplicateEntry("receipt_signers[].role"))
    );
    Ok(())
}

#[test]
fn recipe_phase_order_is_normative() -> TestResult {
    let mut recipe = recipe_body();
    recipe.phases.swap(0, 1);
    assert_eq!(recipe.validate(), Err(FindingError::InvalidField("phases")));

    let mut recipe = recipe_body();
    recipe.phases.pop();
    assert_eq!(recipe.validate(), Err(FindingError::InvalidField("phases")));
    Ok(())
}

#[test]
fn recipe_payload_application_vocabulary_is_phase_specific() {
    let mut recipe = recipe_body();
    recipe.phases[0].payload_application = "apply_patch_v1".to_string();
    assert_eq!(
        recipe.validate(),
        Err(FindingError::InvalidField("phases[].payload_application"))
    );

    let mut recipe = recipe_body();
    recipe.phases[1].payload_application = "replace_tree_v1".to_string();
    assert_eq!(
        recipe.validate(),
        Err(FindingError::InvalidField("phases[].payload_application"))
    );
}

#[test]
fn recipe_unknown_fields_and_wrong_schema_reject() -> TestResult {
    let recipe = recipe_body();
    let mut value = (serde_json::to_value(&recipe))?;
    value["surprise"] = serde_json::json!(true);
    assert!(serde_json::from_value::<FindingReplayRecipeInput>(value).is_err());

    let mut recipe = recipe_body();
    recipe.schema = "chio.finding.replay-recipe-input.v9".to_string();
    assert!(matches!(
        recipe.validate(),
        Err(FindingError::UnsupportedSchema(_))
    ));
    Ok(())
}

#[test]
fn pre_run_template_digest_is_stable_and_validated() -> TestResult {
    let template = FindingPreRunTemplate {
        topic: "rust/workspace/test-failure".to_string(),
        context_sha256: HEX64.to_string(),
        verifier_profile_envelope_sha256: HEX64.to_string(),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: HEX64.to_string(),
        input_bundle_sha256s: vec![HEX64.to_string()],
        environment: recipe_environment(),
        resource_bounds: resource_caps(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        allowed_outcome_classes: vec![FindingOutcomeClass::VerifiedFix],
    };
    (template.validate())?;
    let first = (template.canonical_sha256())?;
    let second = (template.canonical_sha256())?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn terms_reject_currency_mismatch_and_overflow() -> TestResult {
    let seller = keypair(2);
    let mut terms = terms_body(&seller)?;
    terms.backing_requirement.maximum_sale_exposure.currency = "EUR".to_string();
    terms.terms_id = (compute_terms_id(&terms))?;
    assert_eq!(
        terms.validate(),
        Err(FindingError::CurrencyMismatch("backing_requirement"))
    );

    let mut terms = terms_body(&seller)?;
    terms.backing_requirement.base_finding_stake.units = u64::MAX;
    assert_eq!(
        terms.backing_requirement.required_backing_units(),
        Err(FindingError::AmountOverflow("backing_requirement"))
    );
    Ok(())
}

#[test]
fn terms_reject_a_payout_policy_the_settlement_math_does_not_implement() -> TestResult {
    let seller = keypair(2);
    let mut terms = terms_body(&seller)?;
    terms.payout_policy = "winner_takes_all_v1".to_string();
    terms.terms_id = (compute_terms_id(&terms))?;
    assert_eq!(
        terms.validate(),
        Err(FindingError::InvalidField("payout_policy"))
    );
    Ok(())
}

#[test]
fn backing_exposure_cannot_exceed_locked_amount() -> TestResult {
    let collateral = keypair(4);
    let seller = keypair(2);
    let mut backing = backing_body(&collateral, &seller)?;
    backing.maximum_sale_exposure.units = backing.locked_amount.units + 1;
    backing.allocation_id = (compute_allocation_id(&backing))?;
    assert_eq!(
        backing.validate(),
        Err(FindingError::InvalidField("maximum_sale_exposure"))
    );
    Ok(())
}

#[test]
fn report_facets_are_exactly_the_closed_vocabulary_in_order() -> TestResult {
    let verifier = keypair(15);
    let mut report = report_body(&verifier)?;
    report.facets.swap(0, 1);
    report.report_id = (compute_report_id(&report))?;
    assert_eq!(report.validate(), Err(FindingError::InvalidField("facets")));

    let mut report = report_body(&verifier)?;
    report.facets.pop();
    report.report_id = (compute_report_id(&report))?;
    assert_eq!(report.validate(), Err(FindingError::InvalidField("facets")));
    Ok(())
}

#[test]
fn report_bond_backing_verdict_requires_the_named_allocation() -> TestResult {
    let verifier = keypair(15);

    let mut report = report_body(&verifier)?;
    report.backing_allocation_id = None;
    report.report_id = (compute_report_id(&report))?;
    assert_eq!(
        report.validate(),
        Err(FindingError::MissingEntry("backing_allocation_id"))
    );

    let mut report = report_body(&verifier)?;
    for facet in &mut report.facets {
        if facet.facet == FindingFacetKind::BondBacking {
            facet.outcome = FindingFacetOutcome::Unavailable;
        }
    }
    report.report_id = (compute_report_id(&report))?;
    assert_eq!(
        report.validate(),
        Err(FindingError::InvalidField("backing_allocation_id"))
    );
    Ok(())
}

#[test]
fn admission_requires_publication_and_first_epoch_terminals() -> TestResult {
    let venue = keypair(6);

    let mut admission = admission_body(&venue)?;
    admission.fee_terminals.remove(0);
    admission.admission_id = (compute_admission_id(&admission))?;
    assert_eq!(
        admission.validate(),
        Err(FindingError::MissingEntry("fee_terminals[].event"))
    );

    let mut admission = admission_body(&venue)?;
    let duplicate = admission.fee_terminals[0].clone();
    admission.fee_terminals.push(duplicate);
    admission.admission_id = (compute_admission_id(&admission))?;
    assert_eq!(
        admission.validate(),
        Err(FindingError::DuplicateEntry("fee_terminals[].event"))
    );
    Ok(())
}

#[test]
fn admission_pools_must_be_distinct_and_scope_must_bind_the_finding() -> TestResult {
    let venue = keypair(6);

    let mut admission = admission_body(&venue)?;
    admission.challenge_administration_pool.principal_id = "pool:audit".to_string();
    admission.admission_id = (compute_admission_id(&admission))?;
    assert_eq!(
        admission.validate(),
        Err(FindingError::DuplicateEntry("pools"))
    );

    let mut admission = admission_body(&venue)?;
    admission.capability_scope = "finding:someone-else".to_string();
    admission.admission_id = (compute_admission_id(&admission))?;
    assert_eq!(
        admission.validate(),
        Err(FindingError::InvalidField("capability_scope"))
    );
    Ok(())
}

#[test]
fn admission_venue_id_mismatch_rejects() -> TestResult {
    let venue = keypair(6);
    let admission = admission_body(&venue)?;
    let signed = (SignedExportEnvelope::sign(admission, &venue))?;
    assert_eq!(
        verify_signed_admission(&signed, &venue.public_key(), "another-venue"),
        Err(FindingError::AuthorityMismatch("admission"))
    );
    Ok(())
}

#[test]
fn admission_rejects_malformed_backing_fields() -> TestResult {
    let venue = keypair(6);

    let mut admission = admission_body(&venue)?;
    admission.backing_allocation_id = "not-a-hex64-allocation-id".to_string();
    admission.admission_id = (compute_admission_id(&admission))?;
    assert_eq!(
        admission.validate(),
        Err(FindingError::MalformedDigest("backing_allocation_id"))
    );

    let mut admission = admission_body(&venue)?;
    admission.backing_envelope_sha256 = "not-a-hex64-envelope-digest".to_string();
    admission.admission_id = (compute_admission_id(&admission))?;
    assert_eq!(
        admission.validate(),
        Err(FindingError::MalformedDigest("backing_envelope_sha256"))
    );
    Ok(())
}

#[test]
fn market_families_reject_oversized_string_fields() -> TestResult {
    let oversized_id = "i".repeat(MAX_FINDING_IDENTIFIER_BYTES + 1);
    let oversized_text = "t".repeat(MAX_FINDING_TEXT_BYTES + 1);

    let venue = keypair(6);
    let mut admission = admission_body(&venue)?;
    admission.venue_id = oversized_id.clone();
    assert_eq!(
        admission.validate(),
        Err(FindingError::SizeLimitExceeded("venue_id"))
    );

    let issuer = keypair(3);
    let seller = keypair(2);
    let mut authorization = authorization_body(&issuer, &seller)?;
    authorization.revocation_status_ref = oversized_id.clone();
    assert_eq!(
        authorization.validate(),
        Err(FindingError::SizeLimitExceeded("revocation_status_ref"))
    );

    let collateral = keypair(4);
    let mut backing = backing_body(&collateral, &seller)?;
    backing.vault = FindingCollateralVault::VenueLedger {
        ledger_account: oversized_id.clone(),
        operator_epoch: 1,
    };
    assert_eq!(
        backing.validate(),
        Err(FindingError::SizeLimitExceeded("vault.ledger_account"))
    );

    let mut terms = terms_body(&seller)?;
    terms.decision_rule_refs = vec![oversized_id.clone()];
    assert_eq!(
        terms.validate(),
        Err(FindingError::SizeLimitExceeded("decision_rule_refs[]"))
    );

    let mut profile = profile_body()?;
    profile.bbs_projection_issuer.registry_ref = oversized_id.clone();
    assert_eq!(
        profile.validate(),
        Err(FindingError::SizeLimitExceeded(
            "bbs_projection_issuer.registry_ref"
        ))
    );

    let verifier = keypair(15);
    let mut report = report_body(&verifier)?;
    report.facets[0].reason = oversized_text;
    assert_eq!(
        report.validate(),
        Err(FindingError::SizeLimitExceeded("facets[].reason"))
    );
    report.facets[0].reason = "bounded reason".to_string();
    report.facets[0].evidence_refs = vec![oversized_id];
    assert_eq!(
        report.validate(),
        Err(FindingError::SizeLimitExceeded("facets[].evidence_refs[]"))
    );
    Ok(())
}

#[test]
fn market_families_reject_oversized_collections() -> TestResult {
    let venue = keypair(6);
    let mut admission = admission_body(&venue)?;
    admission.fee_terminals = (0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| FindingFeeTerminalBinding {
            fee_schedule_envelope_sha256: HEX64.to_string(),
            event: FindingFeeEvent::ParticipationEpoch {
                epoch_index: index as u64,
            },
            payer: "seller-42".to_string(),
            amount: MonetaryAmount {
                units: 1,
                currency: "USD".to_string(),
            },
            pool_principal_id: "pool:audit".to_string(),
            rail_destination: "rail:venue-ledger:audit-pool".to_string(),
            instruction_sha256: HEX64.to_string(),
            observation_sha256: HEX64.to_string(),
        })
        .collect();
    assert_eq!(
        admission.validate(),
        Err(FindingError::SizeLimitExceeded("fee_terminals"))
    );

    let seller = keypair(2);
    let mut terms = terms_body(&seller)?;
    terms.decision_rule_refs = (0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| format!("decision/rule-{index}"))
        .collect();
    assert_eq!(
        terms.validate(),
        Err(FindingError::SizeLimitExceeded("decision_rule_refs"))
    );

    let mut profile = profile_body()?;
    profile.checkpoint_logs = (0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| FindingCheckpointLogPolicy {
            log_id: format!("checkpoint-{index}"),
            signer: key_policy(14, "checkpoint"),
        })
        .collect();
    assert_eq!(
        profile.validate(),
        Err(FindingError::SizeLimitExceeded("checkpoint_logs"))
    );

    let verifier = keypair(15);
    let mut report = report_body(&verifier)?;
    report.facets[0].evidence_refs = (0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| format!("receipt-{index}"))
        .collect();
    assert_eq!(
        report.validate(),
        Err(FindingError::SizeLimitExceeded("facets[].evidence_refs"))
    );
    Ok(())
}
