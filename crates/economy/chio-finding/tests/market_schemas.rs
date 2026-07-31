//! JSON Schema conformance and golden-fixture coverage for the seven
//! market artifact families. Behavioral wire-type coverage lives in
//! `market_families.rs`; this file pins the registered schemas and the
//! deterministic fixtures against both the schema and the Rust verify
//! paths.

use std::error::Error;
use std::path::PathBuf;

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_finding::{
    compute_admission_id, compute_allocation_id, compute_authorization_id, compute_profile_id,
    compute_report_id, compute_terms_id, signed_envelope_sha256, verify_signed_admission,
    verify_signed_bond_backing, verify_signed_market_terms, verify_signed_seller_authorization,
    verify_signed_verifier_report, FindingAdmission, FindingAuthorityKeyPolicy,
    FindingBackingRequirement, FindingBbsIssuerPolicy, FindingBondBacking, FindingBondClass,
    FindingChallengeBondLimit, FindingChallengeVerifierProfile, FindingCheckpointLogPolicy,
    FindingClaimedVerdict, FindingCollateralVault, FindingError, FindingFacetKind,
    FindingFacetOutcome, FindingFacetResult, FindingFeeEvent, FindingFeeTerminalBinding,
    FindingGuaranteeClass, FindingMarketTerms, FindingPayee, FindingPoolBinding, FindingPredicate,
    FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment, FindingRecipePhase,
    FindingRecipePhaseKind, FindingReplayRecipeInput, FindingResourceCaps,
    FindingSellerAuthorization, FindingVerifierReport, SignedFindingAdmission,
    SignedFindingBondBacking, SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms,
    SignedFindingSellerAuthorization, SignedFindingVerifierReport, FINDING_ADMISSION_SCHEMA_V1,
    FINDING_BOND_BACKING_SCHEMA_V1, FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1,
    FINDING_MARKET_TERMS_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
    FINDING_SELLER_AUTHORIZATION_SCHEMA_V1, FINDING_VERIFIER_REPORT_SCHEMA_V1,
    MAX_FINDING_ARTIFACT_ITEMS, MAX_FINDING_IDENTIFIER_BYTES, MAX_FINDING_TEXT_BYTES,
};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn Error>>;

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// One market family: its registered schema file and its golden fixture.
struct Family {
    schema: &'static str,
    fixture_dir: &'static str,
    fixture_file: &'static str,
}

const PROFILE: Family = Family {
    schema: "challenge-verifier-profile",
    fixture_dir: "verifier-profile-basic",
    fixture_file: "profile.json",
};
const TERMS: Family = Family {
    schema: "market-terms",
    fixture_dir: "market-terms-basic",
    fixture_file: "terms.json",
};
const AUTHORIZATION: Family = Family {
    schema: "seller-authorization",
    fixture_dir: "seller-authorization-basic",
    fixture_file: "authorization.json",
};
const BACKING: Family = Family {
    schema: "bond-backing",
    fixture_dir: "bond-backing-basic",
    fixture_file: "backing.json",
};
const REPORT: Family = Family {
    schema: "verifier-report",
    fixture_dir: "verifier-report-basic",
    fixture_file: "report.json",
};
const ADMISSION: Family = Family {
    schema: "admission",
    fixture_dir: "venue-admission-basic",
    fixture_file: "admission.json",
};
const RECIPE: Family = Family {
    schema: "replay-recipe-input",
    fixture_dir: "replay-recipe-basic",
    fixture_file: "recipe.json",
};

const GOLDEN_PROFILE_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/verifier-profile-basic/profile.json");
const GOLDEN_TERMS_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/market-terms-basic/terms.json");
const GOLDEN_AUTHORIZATION_RAW: &str = include_str!(
    "../../../../fixtures/proof-room/finding/seller-authorization-basic/authorization.json"
);
const GOLDEN_BACKING_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/bond-backing-basic/backing.json");
const GOLDEN_REPORT_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/verifier-report-basic/report.json");
const GOLDEN_ADMISSION_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/venue-admission-basic/admission.json");
const GOLDEN_RECIPE_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/replay-recipe-basic/recipe.json");

const GOLDEN_PROFILE_ID: &str = "26845afc58111332f29b3f5e90766406061d151515e7a0957bafbfc1b1754681";
const GOLDEN_PROFILE_ENVELOPE_SHA256: &str =
    "1cc32ce68d85c5711669e93abf270222796115f4b4a2bc774e457ebb66a04e88";
const GOLDEN_TERMS_ID: &str = "00e03f40ee7e96c48fa13cf05f8f0d932b47cc4524d5fdd06c524d8aa1142e77";
const GOLDEN_TERMS_ENVELOPE_SHA256: &str =
    "3a9cf540163aa9547bc39741e14c30df3afa0f64b65780c6eaca8dfa8ab8af24";
const GOLDEN_AUTHORIZATION_ID: &str =
    "cd595cde853c1d2c42732748e9894cf0166b99bf85df47031eb89d4cf58a2af4";
const GOLDEN_AUTHORIZATION_ENVELOPE_SHA256: &str =
    "04a5959477ee012a70616ed91d6c612849b7be34154744ac60b46dd28a5af66f";
const GOLDEN_ALLOCATION_ID: &str =
    "2586e92a398e6dbbea299408add0610a881a847ec3523e839ef9eb9e175ef482";
const GOLDEN_BACKING_ENVELOPE_SHA256: &str =
    "dd924dc6577ffb36d42a81726652f51121ace3859eebf8fe6edbd5f82bd47f0e";
const GOLDEN_REPORT_ID: &str = "fca3e0c0e15921c334ab431c40010ecc8e881423c529b29766513c3b39fcc186";
const GOLDEN_REPORT_ENVELOPE_SHA256: &str =
    "642276851f5c9ded9cefbfc701ecd95a1c7668ad58e929277ce94070ab5e16a5";
const GOLDEN_ADMISSION_ID: &str =
    "d54f98cf25f7e4ae5812ad1a38ee4b25fe0d007014d09e99c0d7d6f70ef883be";
const GOLDEN_ADMISSION_ENVELOPE_SHA256: &str =
    "8a1e718a55f7500ab56c62f7f806e2d6ca4b4beb6eceebfa39e5b2d69d32fd5c";
const GOLDEN_RECIPE_SHA256: &str =
    "9ac1ef84a974f386b07ced3f0284da47744770e7ea119041c06b837c95e8ddf7";

fn fixture_path(family: &Family) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/proof-room/finding")
        .join(family.fixture_dir)
        .join(family.fixture_file)
}

fn schema_path(family: &Family) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1")
        .join(format!("{}.schema.json", family.schema))
}

fn validate_family_schema(
    family: &Family,
    value: &Value,
) -> Result<(), chio_spec_validate::ValidateError> {
    let path = schema_path(family);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(&path, &schema, &fixture_path(family), value)
}

fn assert_family_schema_rejects(family: &Family, value: &Value, case: &str) -> TestResult {
    match validate_family_schema(family, value) {
        Err(chio_spec_validate::ValidateError::SchemaViolation(_, _, _)) => Ok(()),
        Err(err) => Err(err.into()),
        Ok(()) => Err(std::io::Error::other(format!(
            "{} schema accepted invalid case: {case}",
            family.schema
        ))
        .into()),
    }
}

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
    profile.profile_id = compute_profile_id(&profile)?;
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
    terms.terms_id = compute_terms_id(&terms)?;
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
    authorization.authorization_id = compute_authorization_id(&authorization)?;
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
    backing.allocation_id = compute_allocation_id(&backing)?;
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
    report.report_id = compute_report_id(&report)?;
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
        community_fund_destination: "rail:venue-ledger:community-fund".to_string(),
        status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: 1_700_000_000,
        expires_at: 1_800_000_000,
    };
    admission.admission_id = compute_admission_id(&admission)?;
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

fn signed_profile() -> Result<SignedFindingChallengeVerifierProfile, Box<dyn Error>> {
    Ok(SignedExportEnvelope::sign(profile_body()?, &keypair(1))?)
}

fn signed_terms() -> Result<SignedFindingMarketTerms, Box<dyn Error>> {
    let seller = keypair(2);
    Ok(SignedExportEnvelope::sign(terms_body(&seller)?, &seller)?)
}

fn signed_authorization() -> Result<SignedFindingSellerAuthorization, Box<dyn Error>> {
    let issuer = keypair(3);
    let seller = keypair(2);
    Ok(SignedExportEnvelope::sign(
        authorization_body(&issuer, &seller)?,
        &issuer,
    )?)
}

fn signed_backing() -> Result<SignedFindingBondBacking, Box<dyn Error>> {
    let collateral = keypair(4);
    let seller = keypair(2);
    Ok(SignedExportEnvelope::sign(
        backing_body(&collateral, &seller)?,
        &collateral,
    )?)
}

fn signed_report() -> Result<SignedFindingVerifierReport, Box<dyn Error>> {
    let verifier = keypair(15);
    Ok(SignedExportEnvelope::sign(
        report_body(&verifier)?,
        &verifier,
    )?)
}

fn signed_admission() -> Result<SignedFindingAdmission, Box<dyn Error>> {
    let venue = keypair(6);
    Ok(SignedExportEnvelope::sign(admission_body(&venue)?, &venue)?)
}

#[test]
fn profile_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&PROFILE, &serde_json::to_value(signed_profile()?)?)?;
    Ok(())
}

#[test]
fn profile_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_profile()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&PROFILE, &value, "unknown top-level member")
}

#[test]
fn profile_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_profile()?)?;
    value["body"]["schema"] = json!("chio.finding.challenge-verifier-profile.v999");
    assert_family_schema_rejects(&PROFILE, &value, "wrong schema const")
}

#[test]
fn profile_schema_rejects_missing_receipt_role() -> TestResult {
    let mut value = serde_json::to_value(signed_profile()?)?;
    if let Some(signers) = value["body"]["receipt_signers"].as_array_mut() {
        signers.pop();
    }
    assert_family_schema_rejects(&PROFILE, &value, "two receipt signer roles")
}

#[test]
fn terms_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&TERMS, &serde_json::to_value(signed_terms()?)?)?;
    Ok(())
}

#[test]
fn terms_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&TERMS, &value, "unknown top-level member")
}

#[test]
fn terms_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["body"]["schema"] = json!("chio.finding.market-terms.v999");
    assert_family_schema_rejects(&TERMS, &value, "wrong schema const")
}

#[test]
fn terms_schema_rejects_zero_base_finding_stake() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["body"]["backing_requirement"]["base_finding_stake"]["units"] = json!(0);
    assert_family_schema_rejects(&TERMS, &value, "zero base finding stake")
}

#[test]
fn terms_schema_rejects_unknown_payout_policy() -> TestResult {
    let mut value = serde_json::to_value(signed_terms()?)?;
    value["body"]["payout_policy"] = json!("winner_takes_all_v1");
    assert_family_schema_rejects(&TERMS, &value, "unknown payout policy")
}

#[test]
fn authorization_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(
        &AUTHORIZATION,
        &serde_json::to_value(signed_authorization()?)?,
    )?;
    Ok(())
}

#[test]
fn authorization_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_authorization()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&AUTHORIZATION, &value, "unknown top-level member")
}

#[test]
fn authorization_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_authorization()?)?;
    value["body"]["schema"] = json!("chio.finding.seller-authorization.v999");
    assert_family_schema_rejects(&AUTHORIZATION, &value, "wrong schema const")
}

#[test]
fn authorization_schema_rejects_uppercase_finding_id() -> TestResult {
    let mut value = serde_json::to_value(signed_authorization()?)?;
    value["body"]["finding_id"] = json!(HEX64.to_uppercase());
    assert_family_schema_rejects(&AUTHORIZATION, &value, "uppercase finding_id digest")
}

#[test]
fn backing_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&BACKING, &serde_json::to_value(signed_backing()?)?)?;
    Ok(())
}

#[test]
fn backing_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_backing()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&BACKING, &value, "unknown top-level member")
}

#[test]
fn backing_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_backing()?)?;
    value["body"]["schema"] = json!("chio.finding.bond-backing.v999");
    assert_family_schema_rejects(&BACKING, &value, "wrong schema const")
}

#[test]
fn backing_schema_rejects_zero_claim_horizon() -> TestResult {
    let mut value = serde_json::to_value(signed_backing()?)?;
    value["body"]["claim_horizon_secs"] = json!(0);
    assert_family_schema_rejects(&BACKING, &value, "zero claim horizon")
}

#[test]
fn report_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&REPORT, &serde_json::to_value(signed_report()?)?)?;
    Ok(())
}

#[test]
fn report_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_report()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&REPORT, &value, "unknown top-level member")
}

#[test]
fn report_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_report()?)?;
    value["body"]["schema"] = json!("chio.finding.verifier-report.v999");
    assert_family_schema_rejects(&REPORT, &value, "wrong schema const")
}

#[test]
fn report_schema_rejects_unknown_facet_outcome() -> TestResult {
    let mut value = serde_json::to_value(signed_report()?)?;
    value["body"]["facets"][0]["outcome"] = json!("maybe");
    assert_family_schema_rejects(&REPORT, &value, "unknown facet outcome token")
}

#[test]
fn admission_envelope_conforms_to_schema() -> TestResult {
    validate_family_schema(&ADMISSION, &serde_json::to_value(signed_admission()?)?)?;
    Ok(())
}

#[test]
fn admission_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(signed_admission()?)?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&ADMISSION, &value, "unknown top-level member")
}

#[test]
fn admission_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(signed_admission()?)?;
    value["body"]["schema"] = json!("chio.finding.admission.v999");
    assert_family_schema_rejects(&ADMISSION, &value, "wrong schema const")
}

#[test]
fn admission_schema_rejects_malformed_capability_scope() -> TestResult {
    let mut value = serde_json::to_value(signed_admission()?)?;
    value["body"]["capability_scope"] = json!("finding:not-a-digest");
    assert_family_schema_rejects(&ADMISSION, &value, "malformed capability scope")
}

#[test]
fn market_family_schemas_reject_oversized_string_fields() -> TestResult {
    let oversized_id = "i".repeat(MAX_FINDING_IDENTIFIER_BYTES + 1);
    let oversized_text = "t".repeat(MAX_FINDING_TEXT_BYTES + 1);

    let mut admission = serde_json::to_value(signed_admission()?)?;
    admission["body"]["venue_id"] = json!(oversized_id.clone());
    assert_family_schema_rejects(&ADMISSION, &admission, "oversized venue id")?;

    let mut authorization = serde_json::to_value(signed_authorization()?)?;
    authorization["body"]["revocation_status_ref"] = json!(oversized_id.clone());
    assert_family_schema_rejects(
        &AUTHORIZATION,
        &authorization,
        "oversized revocation status ref",
    )?;

    let mut backing = serde_json::to_value(signed_backing()?)?;
    backing["body"]["vault"]["venue_ledger"]["ledger_account"] = json!(oversized_id.clone());
    assert_family_schema_rejects(&BACKING, &backing, "oversized ledger account")?;

    let mut terms = serde_json::to_value(signed_terms()?)?;
    terms["body"]["payout_policy"] = json!(oversized_id.clone());
    assert_family_schema_rejects(&TERMS, &terms, "oversized payout policy")?;

    let mut profile = serde_json::to_value(signed_profile()?)?;
    profile["body"]["operator"] = json!(oversized_id);
    assert_family_schema_rejects(&PROFILE, &profile, "oversized operator")?;

    let mut report = serde_json::to_value(signed_report()?)?;
    report["body"]["facets"][0]["reason"] = json!(oversized_text);
    assert_family_schema_rejects(&REPORT, &report, "oversized facet reason")
}

#[test]
fn market_family_schemas_reject_oversized_collections() -> TestResult {
    let mut admission = serde_json::to_value(signed_admission()?)?;
    let terminal = admission["body"]["fee_terminals"][0].clone();
    admission["body"]["fee_terminals"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| {
            let mut item = terminal.clone();
            if index > 0 {
                item["event"] = json!({
                    "participation_epoch": {
                        "epoch_index": index - 1
                    }
                });
            }
            item
        })
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&ADMISSION, &admission, "too many fee terminals")?;

    let mut terms = serde_json::to_value(signed_terms()?)?;
    terms["body"]["decision_rule_refs"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| format!("decision/rule-{index}"))
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&TERMS, &terms, "too many decision rules")?;

    let mut profile = serde_json::to_value(signed_profile()?)?;
    let checkpoint = profile["body"]["checkpoint_logs"][0].clone();
    profile["body"]["checkpoint_logs"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| {
            let mut item = checkpoint.clone();
            item["log_id"] = json!(format!("checkpoint-{index}"));
            item
        })
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&PROFILE, &profile, "too many checkpoint logs")?;

    let mut report = serde_json::to_value(signed_report()?)?;
    report["body"]["facets"][0]["evidence_refs"] = json!((0..=MAX_FINDING_ARTIFACT_ITEMS)
        .map(|index| format!("receipt-{index}"))
        .collect::<Vec<_>>());
    assert_family_schema_rejects(&REPORT, &report, "too many evidence refs")
}

#[test]
fn recipe_conforms_to_schema() -> TestResult {
    validate_family_schema(&RECIPE, &serde_json::to_value(recipe_body())?)?;
    Ok(())
}

#[test]
fn recipe_schema_rejects_unknown_top_level_member() -> TestResult {
    let mut value = serde_json::to_value(recipe_body())?;
    value["surprise"] = json!(true);
    assert_family_schema_rejects(&RECIPE, &value, "unknown top-level member")
}

#[test]
fn recipe_schema_rejects_wrong_schema_const() -> TestResult {
    let mut value = serde_json::to_value(recipe_body())?;
    value["schema"] = json!("chio.finding.replay-recipe-input.v999");
    assert_family_schema_rejects(&RECIPE, &value, "wrong schema const")
}

#[test]
fn recipe_schema_rejects_swapped_phase_order() -> TestResult {
    let mut value = serde_json::to_value(recipe_body())?;
    if let Some(phases) = value["phases"].as_array_mut() {
        phases.swap(0, 1);
    }
    assert_family_schema_rejects(&RECIPE, &value, "candidate phase before baseline")
}

#[test]
fn recipe_schema_rejects_unknown_payload_application() -> TestResult {
    let mut value = serde_json::to_value(recipe_body())?;
    value["phases"][1]["payload_application"] = json!("replace_tree_v1");
    assert_family_schema_rejects(&RECIPE, &value, "unknown payload application")
}

#[test]
fn golden_verifier_profile_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_PROFILE_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_PROFILE_RAW)?;
    validate_family_schema(&PROFILE, &value)?;
    let signed: SignedFindingChallengeVerifierProfile = serde_json::from_str(GOLDEN_PROFILE_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    signed.body.validate()?;
    chio_finding::verify_signed_profile(&signed, &keypair(1).public_key())?;
    assert_eq!(signed.body.profile_id, GOLDEN_PROFILE_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_PROFILE_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_market_terms_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_TERMS_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_TERMS_RAW)?;
    validate_family_schema(&TERMS, &value)?;
    let signed: SignedFindingMarketTerms = serde_json::from_str(GOLDEN_TERMS_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_market_terms(&signed)?;
    assert_eq!(signed.body.seller, keypair(2).public_key());
    assert_eq!(signed.body.terms_id, GOLDEN_TERMS_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_TERMS_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_seller_authorization_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_AUTHORIZATION_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_AUTHORIZATION_RAW)?;
    validate_family_schema(&AUTHORIZATION, &value)?;
    let signed: SignedFindingSellerAuthorization = serde_json::from_str(GOLDEN_AUTHORIZATION_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_seller_authorization(&signed)?;
    assert_eq!(signed.body.issuer, keypair(3).public_key());
    assert_eq!(signed.body.authorization_id, GOLDEN_AUTHORIZATION_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_AUTHORIZATION_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_bond_backing_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_BACKING_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_BACKING_RAW)?;
    validate_family_schema(&BACKING, &value)?;
    let signed: SignedFindingBondBacking = serde_json::from_str(GOLDEN_BACKING_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_bond_backing(&signed, &keypair(4).public_key())?;
    assert_eq!(signed.body.allocation_id, GOLDEN_ALLOCATION_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_BACKING_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_verifier_report_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_REPORT_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_REPORT_RAW)?;
    validate_family_schema(&REPORT, &value)?;
    let signed: SignedFindingVerifierReport = serde_json::from_str(GOLDEN_REPORT_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_verifier_report(&signed, &keypair(15).public_key())?;
    assert_eq!(signed.body.report_id, GOLDEN_REPORT_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_REPORT_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_venue_admission_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_ADMISSION_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_ADMISSION_RAW)?;
    validate_family_schema(&ADMISSION, &value)?;
    let signed: SignedFindingAdmission = serde_json::from_str(GOLDEN_ADMISSION_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&signed)?);
    verify_signed_admission(&signed, &keypair(6).public_key(), "venue-wedge")?;
    assert_eq!(signed.body.admission_id, GOLDEN_ADMISSION_ID);
    assert_eq!(
        signed_envelope_sha256(&signed)?,
        GOLDEN_ADMISSION_ENVELOPE_SHA256
    );
    Ok(())
}

#[test]
fn golden_replay_recipe_fixture_validates() -> TestResult {
    let strict_canonical = canonical_json_bytes_from_str(GOLDEN_RECIPE_RAW)?;
    let value: Value = serde_json::from_str(GOLDEN_RECIPE_RAW)?;
    validate_family_schema(&RECIPE, &value)?;
    let recipe: FindingReplayRecipeInput = serde_json::from_str(GOLDEN_RECIPE_RAW)?;
    assert_eq!(strict_canonical, canonical_json_bytes(&recipe)?);
    recipe.validate()?;
    assert_eq!(recipe.canonical_sha256()?, GOLDEN_RECIPE_SHA256);
    Ok(())
}

fn write_fixture<T: serde::Serialize>(family: &Family, artifact: &T) -> TestResult {
    let json = serde_json::to_string_pretty(artifact)?;
    let path = fixture_path(family);
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("golden fixture path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    std::fs::write(path, format!("{json}\n"))?;
    Ok(())
}

#[test]
#[ignore = "regenerates the deterministic golden fixtures; run manually"]
fn regenerate_market_golden_fixtures() -> TestResult {
    write_fixture(&PROFILE, &signed_profile()?)?;
    write_fixture(&TERMS, &signed_terms()?)?;
    write_fixture(&AUTHORIZATION, &signed_authorization()?)?;
    write_fixture(&BACKING, &signed_backing()?)?;
    write_fixture(&REPORT, &signed_report()?)?;
    write_fixture(&ADMISSION, &signed_admission()?)?;
    write_fixture(&RECIPE, &recipe_body())?;
    Ok(())
}
