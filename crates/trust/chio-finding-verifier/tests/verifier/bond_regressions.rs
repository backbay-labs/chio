use super::*;
use chio_finding::{
    compute_terms_id, FindingBackingRequirement, FindingChallengeBondLimit, FindingFacetResult,
    FindingMarketTerms, FINDING_MARKET_TERMS_SCHEMA_V1,
};
use chio_fiscal::fee_schedule::{
    OpenMarketBondClass, OpenMarketBondRequirement, OpenMarketCollateralReferenceKind,
    OpenMarketEconomicsScope, OpenMarketFeeScheduleArtifact,
    OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA,
};

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_owned(),
    }
}

pub(super) fn fixture_terms(
    seller: &Keypair,
    finding: &Finding,
    raw_finding: &str,
    profile_envelope_sha256: &str,
) -> Result<SignedFindingMarketTerms, Box<dyn Error>> {
    let mut terms = FindingMarketTerms {
        schema: FINDING_MARKET_TERMS_SCHEMA_V1.to_string(),
        terms_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: sha256_hex(raw_finding.as_bytes()),
        listing_id: "finding-listing-01".to_string(),
        seller: seller.public_key(),
        backing_requirement: FindingBackingRequirement {
            base_finding_stake: usd(50),
            maximum_sale_exposure: usd(450),
            collateral_policy: "venue_ledger_exclusive_v1".to_string(),
        },
        filing_window_secs: 86_400,
        claim_window_secs: 604_800,
        appeal_window_secs: 259_200,
        audit_epoch_length_secs: 604_800,
        audit_eligible: true,
        decision_rule_refs: vec!["decision/replay-v1".to_string()],
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        challenge_bond_limits: vec![FindingChallengeBondLimit {
            guarantee_class: FindingGuaranteeClass::DeterministicReplay,
            min_bond: usd(10),
            max_bond: usd(100),
        }],
        payout_policy: "pro_rata_capped_v1".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    terms.terms_id = compute_terms_id(&terms)?;
    Ok(SignedExportEnvelope::sign(terms, seller)?)
}

pub(super) fn fixture_fee_schedule(
    authority: &Keypair,
) -> Result<(SignedOpenMarketFeeSchedule, String), Box<dyn Error>> {
    let listing_requirement = OpenMarketBondRequirement {
        bond_class: OpenMarketBondClass::Listing,
        required_amount: MonetaryAmount {
            units: 500,
            currency: "USD".to_owned(),
        },
        collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
        slashable: true,
    };
    let requirement_sha256 = sha256_hex(&canonical_json_bytes(&listing_requirement)?);
    let schedule = SignedExportEnvelope::sign(
        OpenMarketFeeScheduleArtifact {
            schema: OPEN_MARKET_FEE_SCHEDULE_ARTIFACT_SCHEMA.to_owned(),
            fee_schedule_id: "finding-verifier-schedule".to_owned(),
            namespace: "dev.chio.cognition-market".to_owned(),
            governing_operator_id: "venue-operator".to_owned(),
            governing_operator_name: None,
            scope: OpenMarketEconomicsScope {
                namespace: "dev.chio.cognition-market".to_owned(),
                allowed_listing_operator_ids: Vec::new(),
                allowed_actor_kinds: Vec::new(),
                allowed_admission_classes: Vec::new(),
                policy_reference: None,
            },
            publication_fee: usd(1),
            dispute_fee: usd(1),
            market_participation_fee: usd(1),
            bond_requirements: vec![listing_requirement],
            issued_at: 1_699_000_000,
            expires_at: Some(1_900_000_000),
            issued_by: "venue-operator".to_owned(),
            note: None,
        },
        authority,
    )?;
    Ok((schedule, requirement_sha256))
}

fn bond_facet(
    draft: &chio_finding_verifier::FindingVerifierDraft,
) -> Result<&FindingFacetResult, String> {
    draft
        .facets
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::BondBacking)
        .ok_or_else(|| "bond-backing facet missing".to_string())
}

fn rebind_mutated_requirement(
    fx: &Fixture,
    evidence: &mut FindingEvidenceBundle<'_>,
    mutate: impl FnOnce(&mut OpenMarketBondRequirement),
) -> TestResult {
    let snapshot = evidence
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    let requirement = snapshot
        .fee_schedule
        .body
        .bond_requirements
        .first_mut()
        .ok_or("listing requirement missing")?;
    mutate(requirement);
    let requirement_sha256 = sha256_hex(&canonical_json_bytes(&*requirement)?);
    snapshot.fee_schedule = SignedExportEnvelope::sign(
        snapshot.fee_schedule.body.clone(),
        &fx.fee_schedule_authority,
    )?;
    let mut backing = snapshot.backing.body.clone();
    backing.fee_requirement_sha256 = requirement_sha256;
    backing.fee_schedule_envelope_sha256 = signed_envelope_sha256(&snapshot.fee_schedule)?;
    backing.allocation_id = compute_allocation_id(&backing)?;
    snapshot.backing = SignedExportEnvelope::sign(backing, &keypair(4))?;
    snapshot.store_snapshot.body.allocation_id = snapshot.backing.body.allocation_id.clone();
    snapshot.store_snapshot.body.backing_envelope_sha256 =
        signed_envelope_sha256(&snapshot.backing)?;
    snapshot.store_snapshot =
        SignedExportEnvelope::sign(snapshot.store_snapshot.body.clone(), &keypair(4))?;
    Ok(())
}

fn assert_bond_failure(
    fx: &Fixture,
    evidence: &FindingEvidenceBundle<'_>,
    expected_reason: &str,
) -> TestResult {
    let trust = trust_roots(fx);
    let draft = verify_finding_evidence(&fx.raw_finding, &trust, evidence)?;
    let facet = bond_facet(&draft)?;
    assert_eq!(facet.outcome, FindingFacetOutcome::Failed);
    assert!(facet.reason.contains(expected_reason), "{}", facet.reason);
    Ok(())
}

#[test]
fn bond_ref_must_resolve_through_the_signed_store_snapshot() -> TestResult {
    let fx = fixture()?;
    let trust = trust_roots(&fx);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let snapshot = evidence
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    snapshot.store_snapshot.body.bond_ref = "bond:different-requirement".to_string();
    snapshot.store_snapshot =
        SignedExportEnvelope::sign(snapshot.store_snapshot.body.clone(), &keypair(4))?;

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let facet = bond_facet(&draft)?;
    assert_eq!(facet.outcome, FindingFacetOutcome::Failed);
    assert!(facet.reason.contains("different Finding bond_ref"));
    Ok(())
}

#[test]
fn smaller_signed_requirement_cannot_back_larger_sale_exposure() -> TestResult {
    let fx = fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    rebind_mutated_requirement(&fx, &mut evidence, |requirement| {
        requirement.required_amount.units = 1;
    })?;
    assert_bond_failure(
        &fx,
        &evidence,
        "does not cover base stake plus sale exposure",
    )
}

#[test]
fn listing_requirement_must_include_the_base_finding_stake() -> TestResult {
    let fx = fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    rebind_mutated_requirement(&fx, &mut evidence, |requirement| {
        requirement.required_amount.units = 450;
    })?;
    assert_bond_failure(
        &fx,
        &evidence,
        "does not cover base stake plus sale exposure",
    )
}

#[test]
fn locked_allocation_must_include_the_base_finding_stake() -> TestResult {
    let fx = fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let snapshot = evidence
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    let mut backing = snapshot.backing.body.clone();
    backing.locked_amount.units = 450;
    backing.allocation_id = compute_allocation_id(&backing)?;
    snapshot.backing = SignedExportEnvelope::sign(backing, &keypair(4))?;
    snapshot.store_snapshot.body.allocation_id = snapshot.backing.body.allocation_id.clone();
    snapshot.store_snapshot.body.backing_envelope_sha256 =
        signed_envelope_sha256(&snapshot.backing)?;
    snapshot.store_snapshot =
        SignedExportEnvelope::sign(snapshot.store_snapshot.body.clone(), &keypair(4))?;
    assert_bond_failure(
        &fx,
        &evidence,
        "locked allocation does not cover base stake",
    )
}

#[test]
fn signed_requirement_class_and_currency_must_match_the_allocation() -> TestResult {
    let fx = fixture()?;
    let mut wrong_class = bundle(&fx, clone_receipts(&fx));
    rebind_mutated_requirement(&fx, &mut wrong_class, |requirement| {
        requirement.bond_class = OpenMarketBondClass::Dispute;
    })?;
    assert_bond_failure(&fx, &wrong_class, "Listing bond class")?;

    let mut wrong_currency = bundle(&fx, clone_receipts(&fx));
    rebind_mutated_requirement(&fx, &mut wrong_currency, |requirement| {
        requirement.required_amount.currency = "EUR".to_owned();
    })?;
    assert_bond_failure(&fx, &wrong_currency, "currency differs")
}

#[test]
fn backing_must_name_the_exact_signed_fee_schedule() -> TestResult {
    let fx = fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let snapshot = evidence
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    snapshot.fee_schedule.body.note = Some("different signed schedule".to_owned());
    snapshot.fee_schedule = SignedExportEnvelope::sign(
        snapshot.fee_schedule.body.clone(),
        &fx.fee_schedule_authority,
    )?;
    assert_bond_failure(&fx, &evidence, "different fee schedule")
}

#[test]
fn unsupported_collateral_policy_cannot_qualify_bond_backing() -> TestResult {
    let fx = fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let snapshot = evidence
        .bond_snapshot
        .as_mut()
        .ok_or("bond snapshot missing")?;
    let mut terms = snapshot.terms.body.clone();
    terms.backing_requirement.collateral_policy = "external-custodian-v1".to_string();
    terms.terms_id = compute_terms_id(&terms)?;
    snapshot.terms = SignedExportEnvelope::sign(terms, &keypair(2))?;

    let mut backing = snapshot.backing.body.clone();
    backing.terms_envelope_sha256 = signed_envelope_sha256(&snapshot.terms)?;
    backing.allocation_id = compute_allocation_id(&backing)?;
    snapshot.backing = SignedExportEnvelope::sign(backing, &keypair(4))?;
    snapshot.store_snapshot.body.allocation_id = snapshot.backing.body.allocation_id.clone();
    snapshot.store_snapshot.body.backing_envelope_sha256 =
        signed_envelope_sha256(&snapshot.backing)?;
    snapshot.store_snapshot =
        SignedExportEnvelope::sign(snapshot.store_snapshot.body.clone(), &keypair(4))?;

    assert_bond_failure(&fx, &evidence, "backing_requirement.collateral_policy")
}
