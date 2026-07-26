use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_test_support::prelude::*;

use super::*;
use crate::fee_schedule::{
    build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
    OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope, OpenMarketFeeScheduleIssueRequest,
};

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn charter_builder() -> FiscalCharterBuilder {
    FiscalCharterBuilder {
        governing_operator_id: "operator.example".to_string(),
        governed_domains: vec![
            FiscalDomain::TierLimits,
            FiscalDomain::OpenMarketFeeAndBondSchedule,
            FiscalDomain::InsurancePremiumSchedule,
            FiscalDomain::DecisionPremiumBasisPoints,
            FiscalDomain::MarketplaceDiscountPerHundred,
        ],
        signer_keys: vec![key(2).public_key(), key(1).public_key()],
        approval_threshold: 2,
        timelock_seconds: 10,
        proposal_ttl_seconds: 30,
        approval_ttl_seconds: 20,
        issued_at: 10,
        expires_at: 100,
        issued_by: "operator.example".to_string(),
        sequence: 1,
        predecessor_charter_digest: None,
    }
}

fn verified_charter() -> VerifiedFiscalCharter {
    VerifiedFiscalCharter::verify(charter_builder().sign(&key(9)).test_unwrap()).test_unwrap()
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn tier_params() -> FiscalParams {
    FiscalParams::TierLimits {
        ceilings: [usd(100), usd(200), usd(300), usd(400)],
    }
}

fn schedule_builder(domain: FiscalDomain, params: FiscalParams) -> FiscalScheduleBuilder {
    FiscalScheduleBuilder {
        domain,
        params,
        valid_from: 20,
        valid_until: 90,
        issued_at: 20,
        issued_by: "operator.example".to_string(),
    }
}

fn verified_tier_schedule(charter: &VerifiedFiscalCharter) -> VerifiedFiscalSchedule {
    let signed = schedule_builder(FiscalDomain::TierLimits, tier_params())
        .sign(charter, None, &key(9))
        .test_unwrap();
    VerifiedFiscalSchedule::verify(signed, charter, None).test_unwrap()
}

fn resign_charter(mut body: FiscalCharter) -> SignedFiscalCharter {
    body.charter_id = body.expected_id().test_unwrap();
    SignedFiscalCharter::sign(body, &key(9)).test_unwrap()
}

fn resign_schedule(mut body: FiscalSchedule) -> SignedFiscalSchedule {
    body.schedule_id = body.expected_id().test_unwrap();
    SignedFiscalSchedule::sign(body, &key(9)).test_unwrap()
}

fn open_market_params(issued_at: u64, expires_at: Option<u64>) -> FiscalParams {
    let request = OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: "market.example".to_string(),
            allowed_listing_operator_ids: Vec::new(),
            allowed_actor_kinds: Vec::new(),
            allowed_admission_classes: Vec::new(),
            policy_reference: None,
        },
        publication_fee: usd(1),
        dispute_fee: usd(2),
        market_participation_fee: usd(3),
        bond_requirements: vec![OpenMarketBondRequirement {
            bond_class: OpenMarketBondClass::Listing,
            required_amount: usd(10),
            collateral_reference_kind: OpenMarketCollateralReferenceKind::CreditBond,
            slashable: true,
        }],
        issued_by: "operator.example".to_string(),
        issued_at: Some(issued_at),
        expires_at,
        note: None,
    };
    FiscalParams::OpenMarketFeeAndBondSchedule {
        legacy_body: Box::new(
            build_open_market_fee_schedule_artifact("operator.example", None, &request, issued_at)
                .test_unwrap(),
        ),
    }
}

#[test]
fn builders_produce_deterministic_ids_and_canonical_vectors() {
    let mut reordered = charter_builder();
    reordered.governed_domains.reverse();
    reordered.governed_domains.push(FiscalDomain::TierLimits);
    reordered.signer_keys.reverse();
    let first = charter_builder().build_body().test_unwrap();
    let second = reordered.build_body().test_unwrap();
    assert_eq!(first.charter_id, second.charter_id);
    assert_eq!(first.governed_domains, second.governed_domains);
    assert_eq!(first.signer_set, second.signer_set);

    let charter = verified_charter();
    let first_schedule = schedule_builder(FiscalDomain::TierLimits, tier_params())
        .build_body(&charter, None)
        .test_unwrap();
    let second_schedule = schedule_builder(FiscalDomain::TierLimits, tier_params())
        .build_body(&charter, None)
        .test_unwrap();
    assert_eq!(first_schedule.schedule_id, second_schedule.schedule_id);
}

#[test]
fn signer_key_id_hashes_raw_public_key_bytes() {
    let public_key = key(3).public_key();
    let key_id = fiscal_signer_key_id(&public_key).test_unwrap();
    assert_eq!(key_id, sha256_hex(public_key.as_bytes()));
    assert_ne!(key_id, sha256_hex(public_key.to_hex().as_bytes()));
}

#[test]
fn signed_artifacts_verify_and_strictly_decode_canonical_bytes() {
    let charter = verified_charter();
    let charter_bytes = charter.canonical_bytes().test_unwrap();
    assert_eq!(
        VerifiedFiscalCharter::from_canonical_bytes(&charter_bytes)
            .test_unwrap()
            .body()
            .charter_id,
        charter.body().charter_id
    );
    let schedule = verified_tier_schedule(&charter);
    let schedule_bytes = schedule.canonical_bytes().test_unwrap();
    assert_eq!(
        VerifiedFiscalSchedule::from_canonical_bytes(&schedule_bytes, &charter, None)
            .test_unwrap()
            .body()
            .schedule_id,
        schedule.body().schedule_id
    );
    let mut noncanonical = charter_bytes;
    noncanonical.push(b'\n');
    assert!(matches!(
        VerifiedFiscalCharter::from_canonical_bytes(&noncanonical),
        Err(FiscalError::Canonicalization(_))
    ));
}

#[test]
fn strict_charter_rejects_unsorted_duplicate_and_misbound_signers() {
    let valid = charter_builder().build_body().test_unwrap();

    let mut unsorted_domains = valid.clone();
    unsorted_domains.governed_domains.reverse();
    assert!(matches!(
        VerifiedFiscalCharter::verify(resign_charter(unsorted_domains)),
        Err(FiscalError::InvalidField("governed_domains.order"))
    ));

    let mut duplicate_domain = valid.clone();
    duplicate_domain
        .governed_domains
        .insert(1, duplicate_domain.governed_domains[0]);
    assert!(matches!(
        VerifiedFiscalCharter::verify(resign_charter(duplicate_domain)),
        Err(FiscalError::InvalidField("governed_domains.order"))
    ));

    let mut unsorted_signers = valid.clone();
    unsorted_signers.signer_set.reverse();
    assert!(matches!(
        VerifiedFiscalCharter::verify(resign_charter(unsorted_signers)),
        Err(FiscalError::InvalidField("signer_set.order"))
    ));

    let mut duplicate_signer = valid.clone();
    duplicate_signer
        .signer_set
        .insert(1, duplicate_signer.signer_set[0].clone());
    assert!(matches!(
        VerifiedFiscalCharter::verify(resign_charter(duplicate_signer)),
        Err(FiscalError::InvalidField("signer_set.public_key_unique"))
    ));

    let mut wrong_key_id = valid;
    wrong_key_id.signer_set[0].key_id = "0".repeat(64);
    assert!(matches!(
        VerifiedFiscalCharter::verify(resign_charter(wrong_key_id)),
        Err(FiscalError::InvalidField("signer_set.key_id_binding"))
    ));
}

#[test]
fn charter_rejects_invalid_threshold_durations_expiry_and_lineage() {
    let cases = [
        {
            let mut value = charter_builder();
            value.approval_threshold = 0;
            value
        },
        {
            let mut value = charter_builder();
            value.approval_threshold = 3;
            value
        },
        {
            let mut value = charter_builder();
            value.timelock_seconds = 0;
            value
        },
        {
            let mut value = charter_builder();
            value.proposal_ttl_seconds = value.timelock_seconds;
            value
        },
        {
            let mut value = charter_builder();
            value.expires_at = value.issued_at;
            value
        },
        {
            let mut value = charter_builder();
            value.sequence = 2;
            value
        },
        {
            let mut value = charter_builder();
            value.predecessor_charter_digest = Some("1".repeat(64));
            value
        },
    ];
    for case in cases {
        assert!(case.build_body().is_err());
    }
}

#[test]
fn params_reject_currency_and_numeric_contract_violations() {
    let mut mixed = [usd(100), usd(200), usd(300), usd(400)];
    mixed[3].currency = "EUR".to_string();
    let invalid = [
        FiscalParams::TierLimits { ceilings: mixed },
        FiscalParams::TierLimits {
            ceilings: [usd(100), usd(90), usd(300), usd(400)],
        },
        FiscalParams::MarketplaceDiscountPerHundred {
            discounts: [0, 25, 101, 100],
        },
        FiscalParams::MarketplaceDiscountPerHundred {
            discounts: [0, 50, 40, 100],
        },
        FiscalParams::DecisionPremiumBasisPoints {
            approve: [100, 90, 300, 400],
            reduce_ceiling: [100, 200, 300, 400],
        },
        FiscalParams::DecisionPremiumBasisPoints {
            approve: [100, 200, 300, 400],
            reduce_ceiling: [100, 199, 300, 400],
        },
        FiscalParams::InsurancePremiumSchedule {
            decline_floor: 500,
            high_risk_floor: 500,
            medium_risk_floor: 700,
            low_risk_floor: 1001,
            score_adjustments_bps: [10_000, 20_000, 50_000],
            behavioral_threshold: 3.0,
            behavioral_penalty_per_sigma: 50,
            behavioral_penalty_cap: 250,
        },
        FiscalParams::InsurancePremiumSchedule {
            decline_floor: 500,
            high_risk_floor: 500,
            medium_risk_floor: 700,
            low_risk_floor: 900,
            score_adjustments_bps: [10_000, 50_000, 20_000],
            behavioral_threshold: f64::INFINITY,
            behavioral_penalty_per_sigma: 50,
            behavioral_penalty_cap: 250,
        },
    ];
    for params in invalid {
        assert!(params.validate().is_err());
    }
}

#[test]
fn schedule_rejects_domain_charter_expiry_and_currency_mismatch() {
    let charter = verified_charter();
    assert!(
        schedule_builder(FiscalDomain::InsurancePremiumSchedule, tier_params())
            .build_body(&charter, None)
            .is_err()
    );

    let mut invalid_currency = tier_params();
    if let FiscalParams::TierLimits { ceilings } = &mut invalid_currency {
        ceilings[0].currency = "usd".to_string();
    }
    assert!(schedule_builder(FiscalDomain::TierLimits, invalid_currency)
        .build_body(&charter, None)
        .is_err());

    let mut expired = schedule_builder(FiscalDomain::TierLimits, tier_params());
    expired.valid_until = charter.body().expires_at + 1;
    assert!(expired.build_body(&charter, None).is_err());

    let schedule = verified_tier_schedule(&charter);
    let mut wrong_charter = schedule.body().clone();
    wrong_charter.charter_digest = "1".repeat(64);
    assert!(matches!(
        VerifiedFiscalSchedule::verify(resign_schedule(wrong_charter), &charter, None),
        Err(FiscalError::InvalidCharterBinding)
    ));
}

#[test]
fn schedule_rejects_lineage_gaps_and_cross_domain_predecessors() {
    let charter = verified_charter();
    let predecessor = verified_tier_schedule(&charter);
    let successor = schedule_builder(FiscalDomain::TierLimits, tier_params())
        .sign(&charter, Some(&predecessor), &key(9))
        .test_unwrap();
    assert_eq!(
        VerifiedFiscalSchedule::verify(successor, &charter, Some(&predecessor))
            .test_unwrap()
            .body()
            .sequence,
        2
    );

    let mut gap = schedule_builder(FiscalDomain::TierLimits, tier_params())
        .build_body(&charter, Some(&predecessor))
        .test_unwrap();
    gap.sequence = 3;
    assert!(matches!(
        VerifiedFiscalSchedule::verify(resign_schedule(gap), &charter, Some(&predecessor)),
        Err(FiscalError::InvalidLineage)
    ));

    assert!(schedule_builder(
        FiscalDomain::MarketplaceDiscountPerHundred,
        FiscalParams::MarketplaceDiscountPerHundred {
            discounts: [0, 10, 20, 30],
        },
    )
    .build_body(&charter, Some(&predecessor))
    .is_err());

    let mut successor_builder = charter_builder();
    successor_builder.sequence = 2;
    successor_builder.predecessor_charter_digest = Some(charter.digest().to_string());
    let successor_charter =
        VerifiedFiscalCharter::verify(successor_builder.sign(&key(9)).test_unwrap()).test_unwrap();
    let replacement = schedule_builder(FiscalDomain::TierLimits, tier_params())
        .sign_rotation_replacement(&successor_charter, &predecessor, &key(9))
        .test_unwrap();
    assert_eq!(
        VerifiedFiscalSchedule::verify_rotation_replacement(
            replacement,
            &successor_charter,
            &predecessor,
        )
        .test_unwrap()
        .body()
        .sequence,
        2
    );

    let mut unrelated_builder = charter_builder();
    unrelated_builder.sequence = 2;
    unrelated_builder.predecessor_charter_digest = Some("1".repeat(64));
    let unrelated =
        VerifiedFiscalCharter::verify(unrelated_builder.sign(&key(9)).test_unwrap()).test_unwrap();
    assert!(schedule_builder(FiscalDomain::TierLimits, tier_params())
        .build_rotation_replacement(&unrelated, &predecessor)
        .is_err());
}

#[test]
fn open_market_schedule_requires_exact_operator_and_time_binding() {
    let charter = verified_charter();
    let valid = schedule_builder(
        FiscalDomain::OpenMarketFeeAndBondSchedule,
        open_market_params(20, Some(90)),
    )
    .build_body(&charter, None)
    .test_unwrap();
    assert_eq!(valid.domain, FiscalDomain::OpenMarketFeeAndBondSchedule);

    assert!(schedule_builder(
        FiscalDomain::OpenMarketFeeAndBondSchedule,
        open_market_params(19, Some(90)),
    )
    .build_body(&charter, None)
    .is_err());
    assert!(schedule_builder(
        FiscalDomain::OpenMarketFeeAndBondSchedule,
        open_market_params(20, None),
    )
    .build_body(&charter, None)
    .is_err());

    let mut wrong_operator = open_market_params(20, Some(90));
    if let FiscalParams::OpenMarketFeeAndBondSchedule { legacy_body } = &mut wrong_operator {
        legacy_body.governing_operator_id = "attacker.example".to_string();
    }
    assert!(
        schedule_builder(FiscalDomain::OpenMarketFeeAndBondSchedule, wrong_operator,)
            .build_body(&charter, None)
            .is_err()
    );
}

#[test]
fn unknown_schema_self_id_and_signature_tamper_fail_closed() {
    let valid = charter_builder().build_body().test_unwrap();
    let mut unknown = valid.clone();
    unknown.schema = "chio.fiscal.charter.v9".to_string();
    assert!(matches!(
        VerifiedFiscalCharter::verify(resign_charter(unknown)),
        Err(FiscalError::UnknownSchema(_))
    ));

    let mut bad_id = valid.clone();
    bad_id.charter_id = "0".repeat(64);
    let bad_id = SignedFiscalCharter::sign(bad_id, &key(9)).test_unwrap();
    assert!(matches!(
        VerifiedFiscalCharter::verify(bad_id),
        Err(FiscalError::InvalidSelfId)
    ));

    let mut bad_signature = SignedFiscalCharter::sign(valid.clone(), &key(9)).test_unwrap();
    bad_signature.signature = SignedExportEnvelope::sign(valid, &key(8))
        .test_unwrap()
        .signature;
    assert!(matches!(
        VerifiedFiscalCharter::verify(bad_signature),
        Err(FiscalError::InvalidSignature)
    ));

    let charter = verified_charter();
    let schedule = verified_tier_schedule(&charter);
    let mut unknown_schedule = schedule.body().clone();
    unknown_schedule.schema = "chio.fiscal.schedule.v9".to_string();
    assert!(matches!(
        VerifiedFiscalSchedule::verify(resign_schedule(unknown_schedule), &charter, None),
        Err(FiscalError::UnknownSchema(_))
    ));

    let mut bad_schedule_id = schedule.body().clone();
    bad_schedule_id.schedule_id = "0".repeat(64);
    let signed = SignedFiscalSchedule::sign(bad_schedule_id, &key(9)).test_unwrap();
    assert!(matches!(
        VerifiedFiscalSchedule::verify(signed, &charter, None),
        Err(FiscalError::InvalidSelfId)
    ));
}
