#![cfg(feature = "cognition-market-experimental")]

//! Feature-gated coverage for the admission-gated bid seam:
//! `verify_finding_admission` over externally pinned inputs, then
//! `bid_with_finding_admission` delegating to the REAL marketplace
//! `bid()` path for a `finding:<finding_id>` scoped listing.
//!
//! Fixtures use deterministic seeds mirroring the builders in
//! `chio-finding/tests/market_families.rs`; the fiscal resolver is
//! assembled from the checked-in chio-fiscal fixtures exactly like
//! `chio-market/tests/insurance_flow.rs`.

use chio_core_types::crypto::sha256_hex;
use chio_core_types::merkle::MerkleTree;
use chio_core_types::SigningAlgorithm;
use chio_finding::{
    compute_admission_id, compute_allocation_id, compute_finding_id, compute_terms_id,
    sign_finding, signed_envelope_sha256, Finding, FindingAdmission, FindingAuthorityKeyPolicy,
    FindingBackingRequirement, FindingBondBacking, FindingBondClass, FindingChallengeBondLimit,
    FindingCollateralVault, FindingDescriptor, FindingError, FindingEvidenceClass, FindingFeeEvent,
    FindingFeeTerminalBinding, FindingGuaranteeClass, FindingMarketTerms, FindingOutcomeClass,
    FindingPoolBinding, SignedFindingAdmission, SignedFindingBondBacking, SignedFindingMarketTerms,
    FINDING_ADMISSION_SCHEMA_V1, FINDING_BOND_BACKING_SCHEMA_V1, FINDING_MARKET_TERMS_SCHEMA_V1,
    FINDING_SCHEMA_V1,
};
use chio_fiscal::{
    FiscalActivationHistory, FiscalAuthorityState, FiscalBootstrapState, FiscalCharterRegistry,
    FiscalContinuitySnapshot, FiscalGenesisPolicy, FiscalResolver, FiscalRuntimeAdapter,
    FiscalRuntimeAdapterRegistry, SignedFiscalCharter, SignedFiscalContinuityCheckpoint,
    SignedFiscalRuntimeReadiness, VerifiedFiscalCharter, VerifiedFiscalContinuityCheckpoint,
    VerifiedFiscalRuntimeReadiness, FISCAL_RUNTIME_ADAPTER_COUNT,
};
use chio_open_market::canonical_json_bytes;
use chio_open_market::{
    bidding::{BidMintContext, BidRequest, RequestedScope, SignedBidRequest, BID_REQUEST_SCHEMA},
    capability::scope::MonetaryAmount,
    crypto::{Keypair, PublicKey},
    evaluation::OpenMarketPenaltyEvaluation,
    evidence::{OpenMarketFinding, OpenMarketFindingCode},
    fee_schedule::{
        build_open_market_fee_schedule_artifact, OpenMarketBondClass, OpenMarketBondRequirement,
        OpenMarketCollateralReferenceKind, OpenMarketEconomicsScope,
        OpenMarketFeeScheduleIssueRequest, SignedOpenMarketFeeSchedule,
    },
    finding_admission::{
        accept_finding_purchase, bid_with_finding_admission, bid_with_finding_purchase,
        verify_finding_admission, verify_finding_admission_for_activation, FindingAdmissionContext,
        FindingAdmissionError, FindingAdmissionPenaltyGate, FindingAllocationSnapshot,
        FindingAllocationStatus, FindingConstituentExpiryBounds, FindingFeeScheduleGate,
    },
    finding_pheromone::{
        admit_and_resolve_finding_pheromone_hint, finding_pheromone_subject_policy,
        FindingPheromoneConvention, FindingPheromoneError, FindingPheromoneIndicator,
        FINDING_PHEROMONE_CONFIDENCE, FINDING_PHEROMONE_DECAY_HALF_LIFE_SECS,
        FINDING_PHEROMONE_EVAPORATION_FLOOR, FINDING_PHEROMONE_INDICATOR_SCHEMA_V1,
        FINDING_PHEROMONE_SUBJECT_CLASS, FINDING_PHEROMONE_SUBJECT_NAMESPACE,
    },
    fiscal_adapter::signed_fee_schedule_digest,
    listing::{
        GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole, Listing,
        ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
        GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    },
    penalty::{OpenMarketPenaltyAction, OpenMarketPenaltyEffectiveState, OpenMarketPenaltyState},
};
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, scarcity_policy_sha256,
    scarcity_window_id, sign_deposit, InMemoryPheromoneSubstrate, ObservationCostVerificationMode,
    PassportAdmission, PheromoneCostCommitment, PheromoneDeposit, PheromoneDepositBody,
    PheromoneObservationCostAmount, PheromoneObservationCostLeaf,
    PheromoneObservationCostStatement, PheromoneObservationCostTelemetryRoot,
    PheromoneObservationCostVerifierRoot, PheromoneObservationCostVerifierRootBody,
    PheromoneRuntimeTrustFloorEntry, PheromoneRuntimeTrustFloorState, PheromoneScarcityPolicy,
    PheromoneValidationContext, Severity, OBSERVATION_COST_TELEMETRY_ALGORITHM,
    OBSERVATION_COST_UNIT, PHEROMONE_COST_COMMITMENT_SCHEMA, PHEROMONE_DEPOSIT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA, PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA, PHEROMONE_SCARCITY_POLICY_SCHEMA,
};
use chio_test_support::prelude::*;

const VENUE_ID: &str = "venue-wedge";
const FINDING_SERVER_ID: &str = "finding-server.seller.example";
const FINDING_LISTING_ID: &str = "listing-finding-admitted-0001";
const NOW: u64 = 1_750_000_000;
const ADMISSION_ISSUED_AT: u64 = 1_700_000_000;
const ADMISSION_EXPIRES_AT: u64 = 1_790_000_000;
/// The finding's own expiry: the caller-resolved earliest bound for the
/// constituents the admission carries only as digests.
const CONSTITUENT_EXPIRES_AT: u64 = 1_792_656_000;
const WINDOW_EXPIRES_AT: u64 = 1_900_000_000;
const STAKE_UNITS: u64 = 50;
const EXPOSURE_UNITS: u64 = 450;
const LOCKED_UNITS: u64 = 500;
const REQUIREMENT_UNITS: u64 = 5_000;

fn hex64(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn key_policy(seed: u8, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: ADMISSION_ISSUED_AT,
        valid_until: WINDOW_EXPIRES_AT,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

/// Fallback-mode fiscal resolver built from the checked-in chio-fiscal
/// fixtures (`chio-market/tests/insurance_flow.rs` precedent). The
/// open-market domain has never been activated there, so
/// `authorize_fiscal_open_market_fee_schedule` verifies the legacy
/// schedule against the trusted local operator signers.
fn with_fiscal<T>(run: impl FnOnce(&FiscalResolver<'_>) -> T) -> T {
    let fixture = |name: &str| {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
        ));
        std::fs::read(path).test_expect("read fiscal fixture")
    };
    let policy: FiscalGenesisPolicy =
        serde_json::from_slice(&fixture("genesis-policy")).test_expect("genesis policy");
    let charter = VerifiedFiscalCharter::verify(
        serde_json::from_slice::<SignedFiscalCharter>(&fixture("charter")).test_expect("charter"),
    )
    .test_expect("verified charter");
    let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()])
        .test_expect("fiscal charter registry");
    let registry = FiscalRuntimeAdapterRegistry::new(
        "build-1".to_owned(),
        "chio.fiscal.runtime.v1".to_owned(),
        (0..FISCAL_RUNTIME_ADAPTER_COUNT)
            .map(|index| {
                FiscalRuntimeAdapter::new(format!("adapter-{index}"), format!("1.{index}"))
                    .test_expect("runtime adapter")
            })
            .collect(),
    )
    .test_expect("runtime registry");
    let readiness = VerifiedFiscalRuntimeReadiness::verify(
        serde_json::from_slice::<SignedFiscalRuntimeReadiness>(&fixture("consumer-readiness"))
            .test_expect("consumer readiness"),
        &policy,
        registry,
    )
    .test_expect("verified consumer readiness");
    let checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
        serde_json::from_slice::<SignedFiscalContinuityCheckpoint>(&fixture(
            "continuity-checkpoint",
        ))
        .test_expect("continuity checkpoint"),
        &policy,
        &charters,
    )
    .test_expect("verified continuity checkpoint");
    let authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &checkpoint,
        FiscalBootstrapState::CharterPinned,
    )
    .test_expect("fiscal authority state");
    let history = FiscalActivationHistory::new(Vec::new()).test_expect("empty activation history");
    run(&FiscalResolver {
        continuity: FiscalContinuitySnapshot::Verified(&checkpoint),
        policy: &policy,
        readiness: &readiness,
        activation_history: &history,
        authority: &authority,
        charters: &charters,
        schedules: &[],
        verify_at: checkpoint.body().trusted_clock_high_water,
    })
}

fn sealed_finding() -> Finding {
    let issuer = keypair(11);
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#flaky-suite-investigation".to_string(),
            context_sha256: hex64('a'),
            outcome_class: FindingOutcomeClass::NullResult,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: hex64('b'),
        payload_media_type: "application/json".to_string(),
        evidence_receipt_ids: vec!["receipt-0001".to_string(), "receipt-0002".to_string()],
        evidence_checkpoint_ref: "checkpoint-0001".to_string(),
        evidence_cost: usd(4_200),
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some(hex64('c')),
        intent_commitment_receipt_id: None,
        bond_ref: "bond-req-listing-slashable-01".to_string(),
        status_feed_ref: "finding-status-feed-01".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: issuer.public_key(),
        issued_at: ADMISSION_ISSUED_AT,
        expires_at: CONSTITUENT_EXPIRES_AT,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding).test_expect("finding id");
    sign_finding(finding, &issuer).test_expect("sign finding")
}

fn signed_schedule(
    operator: &Keypair,
    requirement_units: u64,
    slashable: bool,
    currency: &str,
) -> SignedOpenMarketFeeSchedule {
    let request = OpenMarketFeeScheduleIssueRequest {
        scope: OpenMarketEconomicsScope {
            namespace: "https://market.seller.example".to_string(),
            allowed_listing_operator_ids: Vec::new(),
            allowed_actor_kinds: Vec::new(),
            allowed_admission_classes: Vec::new(),
            policy_reference: None,
        },
        publication_fee: usd(5),
        dispute_fee: usd(25),
        market_participation_fee: usd(3),
        bond_requirements: vec![OpenMarketBondRequirement {
            bond_class: OpenMarketBondClass::Listing,
            required_amount: MonetaryAmount {
                units: requirement_units,
                currency: currency.to_string(),
            },
            collateral_reference_kind: OpenMarketCollateralReferenceKind::ExternalReference,
            slashable,
        }],
        issued_by: "governance@seller.example".to_string(),
        issued_at: Some(ADMISSION_ISSUED_AT),
        expires_at: None,
        note: None,
    };
    let artifact = build_open_market_fee_schedule_artifact(
        "https://market.seller.example",
        None,
        &request,
        ADMISSION_ISSUED_AT,
    )
    .test_expect("build fee schedule");
    SignedOpenMarketFeeSchedule::sign(artifact, operator).test_expect("sign fee schedule")
}

fn signed_terms(seller: &Keypair, finding: &Finding, expires_at: u64) -> SignedFindingMarketTerms {
    let mut terms = FindingMarketTerms {
        schema: FINDING_MARKET_TERMS_SCHEMA_V1.to_string(),
        terms_id: String::new(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: hex64('d'),
        listing_id: FINDING_LISTING_ID.to_string(),
        seller: seller.public_key(),
        backing_requirement: FindingBackingRequirement {
            base_finding_stake: usd(STAKE_UNITS),
            maximum_sale_exposure: usd(EXPOSURE_UNITS),
            collateral_policy: "venue_ledger_exclusive_v1".to_string(),
        },
        filing_window_secs: 86_400,
        claim_window_secs: 604_800,
        appeal_window_secs: 259_200,
        audit_epoch_length_secs: 2_592_000,
        audit_eligible: true,
        decision_rule_refs: vec!["decision/replay-v1".to_string()],
        verifier_profile_envelope_sha256: hex64('3'),
        challenge_bond_limits: vec![FindingChallengeBondLimit {
            guarantee_class: FindingGuaranteeClass::DeterministicReplay,
            min_bond: usd(10),
            max_bond: usd(100),
        }],
        payout_policy: "pro_rata_capped_v1".to_string(),
        issued_at: ADMISSION_ISSUED_AT,
        expires_at,
    };
    terms.terms_id = compute_terms_id(&terms).test_expect("terms id");
    SignedFindingMarketTerms::sign(terms, seller).test_expect("sign terms")
}

fn signed_backing(
    collateral: &Keypair,
    seller: &Keypair,
    finding: &Finding,
    fee_schedule_envelope_sha256: &str,
    terms_envelope_sha256: &str,
) -> SignedFindingBondBacking {
    signed_backing_committing(
        collateral,
        seller,
        finding,
        fee_schedule_envelope_sha256,
        LOCKED_UNITS,
        terms_envelope_sha256,
    )
}

fn signed_backing_committing(
    collateral: &Keypair,
    seller: &Keypair,
    finding: &Finding,
    fee_schedule_envelope_sha256: &str,
    locked_units: u64,
    terms_envelope_sha256: &str,
) -> SignedFindingBondBacking {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: collateral.public_key(),
        seller: seller.public_key(),
        authorization_envelope_sha256: hex64('1'),
        finding_id: finding.finding_id.clone(),
        listing_id: FINDING_LISTING_ID.to_string(),
        terms_envelope_sha256: terms_envelope_sha256.to_string(),
        profile_envelope_sha256: hex64('3'),
        fee_requirement_sha256: hex64('4'),
        fee_schedule_envelope_sha256: fee_schedule_envelope_sha256.to_string(),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(locked_units),
        maximum_sale_exposure: usd(EXPOSURE_UNITS),
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: "vault:finding-collateral".to_string(),
            operator_epoch: 1,
        },
        issued_at: ADMISSION_ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
    };
    backing.allocation_id = compute_allocation_id(&backing).test_expect("allocation id");
    SignedFindingBondBacking::sign(backing, collateral).test_expect("sign backing")
}

struct AdmissionBindings {
    listing_envelope_sha256: String,
    pricing_hint_envelope_sha256: String,
    terms_envelope_sha256: String,
    backing_envelope_sha256: String,
    backing_allocation_id: String,
    fee_schedule_envelope_sha256: String,
    issued_at: u64,
    expires_at: u64,
}

fn signed_admission(
    venue: &Keypair,
    finding: &Finding,
    bindings: &AdmissionBindings,
) -> SignedFindingAdmission {
    let mut admission = FindingAdmission {
        schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
        admission_id: String::new(),
        venue: venue.public_key(),
        venue_id: VENUE_ID.to_string(),
        finding_id: finding.finding_id.clone(),
        finding_artifact_sha256: hex64('d'),
        seller_authorization_envelope_sha256: hex64('1'),
        listing_id: FINDING_LISTING_ID.to_string(),
        listing_envelope_sha256: bindings.listing_envelope_sha256.clone(),
        server_id: FINDING_SERVER_ID.to_string(),
        metadata_url: format!(
            "https://registry.seller.example/finding/{}",
            finding.finding_id
        ),
        pricing_hint_envelope_sha256: bindings.pricing_hint_envelope_sha256.clone(),
        capability_scope: format!("finding:{}", finding.finding_id),
        publisher_operator_id: "seller-operator".to_string(),
        payee_destination: "rail:venue-ledger:seller-42".to_string(),
        fee_schedule_envelope_sha256: bindings.fee_schedule_envelope_sha256.to_string(),
        verifier_report_id: hex64('7'),
        verifier_report_envelope_sha256: hex64('8'),
        terms_envelope_sha256: bindings.terms_envelope_sha256.to_string(),
        profile_envelope_sha256: hex64('3'),
        fee_terminals: vec![
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: bindings.fee_schedule_envelope_sha256.to_string(),
                event: FindingFeeEvent::Publication,
                payer: "seller-42".to_string(),
                amount: usd(5),
                pool_principal_id: "pool:audit".to_string(),
                rail_destination: "rail:venue-ledger:audit-pool".to_string(),
                instruction_sha256: hex64('9'),
                observation_sha256: hex64('a'),
            },
            FindingFeeTerminalBinding {
                fee_schedule_envelope_sha256: bindings.fee_schedule_envelope_sha256.to_string(),
                event: FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                payer: "seller-42".to_string(),
                amount: usd(3),
                pool_principal_id: "pool:audit".to_string(),
                rail_destination: "rail:venue-ledger:audit-pool".to_string(),
                instruction_sha256: hex64('b'),
                observation_sha256: hex64('c'),
            },
        ],
        backing_allocation_id: bindings.backing_allocation_id.to_string(),
        backing_envelope_sha256: bindings.backing_envelope_sha256.to_string(),
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
        issued_at: bindings.issued_at,
        expires_at: bindings.expires_at,
    };
    admission.admission_id = compute_admission_id(&admission).test_expect("admission id");
    SignedFindingAdmission::sign(admission, venue).test_expect("sign admission")
}

/// The full artifact web behind one admitted finding listing.
struct Web {
    operator: Keypair,
    venue: Keypair,
    seller: Keypair,
    venue_key: PublicKey,
    collateral_key: PublicKey,
    trusted_signers: Vec<PublicKey>,
    finding: Finding,
    schedule: SignedOpenMarketFeeSchedule,
    schedule_sha256: String,
    terms: SignedFindingMarketTerms,
    terms_sha256: String,
    backing: SignedFindingBondBacking,
    backing_sha256: String,
    listing_sha256: String,
    hint_sha256: String,
    admission: SignedFindingAdmission,
}

fn web_with_schedule(requirement_units: u64, slashable: bool, currency: &str) -> Web {
    let operator = keypair(21);
    let venue = keypair(6);
    let seller = keypair(2);
    let collateral = keypair(4);
    let finding = sealed_finding();
    let schedule = signed_schedule(&operator, requirement_units, slashable, currency);
    let schedule_sha256 = signed_fee_schedule_digest(&schedule).test_expect("schedule digest");
    let terms = signed_terms(&seller, &finding, WINDOW_EXPIRES_AT);
    let terms_sha256 = signed_envelope_sha256(&terms).test_expect("terms digest");
    let backing = signed_backing(
        &collateral,
        &seller,
        &finding,
        &schedule_sha256,
        &terms_sha256,
    );
    let backing_sha256 = signed_envelope_sha256(&backing).test_expect("backing digest");
    // The admission binds the exact listing and pricing-hint envelopes a
    // bid must later present, so build the canonical entry here.
    let canonical_listing = finding_listing_entry(
        &operator,
        &finding,
        &format!("finding:{}", finding.finding_id),
        900,
    );
    let listing_sha256 =
        signed_envelope_sha256(&canonical_listing.listing).test_expect("listing digest");
    let hint_sha256 = signed_envelope_sha256(&canonical_listing.pricing).test_expect("hint digest");
    let admission = signed_admission(
        &venue,
        &finding,
        &AdmissionBindings {
            listing_envelope_sha256: listing_sha256.clone(),
            pricing_hint_envelope_sha256: hint_sha256.clone(),
            terms_envelope_sha256: terms_sha256.clone(),
            backing_envelope_sha256: backing_sha256.clone(),
            backing_allocation_id: backing.body.allocation_id.clone(),
            fee_schedule_envelope_sha256: schedule_sha256.clone(),
            issued_at: ADMISSION_ISSUED_AT,
            expires_at: ADMISSION_EXPIRES_AT,
        },
    );
    Web {
        venue_key: venue.public_key(),
        collateral_key: collateral.public_key(),
        trusted_signers: vec![operator.public_key()],
        operator,
        venue,
        seller,
        finding,
        schedule,
        schedule_sha256,
        terms,
        terms_sha256,
        backing,
        backing_sha256,
        listing_sha256,
        hint_sha256,
        admission,
    }
}

fn base_web() -> Web {
    web_with_schedule(REQUIREMENT_UNITS, true, "USD")
}

impl Web {
    fn context<'a>(&'a self, resolver: &'a FiscalResolver<'a>) -> FindingAdmissionContext<'a> {
        FindingAdmissionContext {
            venue_authority: &self.venue_key,
            venue_id: VENUE_ID,
            now: NOW,
            fee_schedule: &self.schedule,
            fee_schedule_gate: FindingFeeScheduleGate::Fiscal {
                resolver,
                binding: None,
            },
            trusted_local_operator_signers: &self.trusted_signers,
            terms: &self.terms,
            backing: &self.backing,
            allocation_snapshot: FindingAllocationSnapshot {
                allocation_id: self.backing.body.allocation_id.clone(),
                backing_envelope_sha256: self.backing_sha256.clone(),
                expires_at: self.backing.body.expires_at,
                status: FindingAllocationStatus::Consumed,
                active_admission_id: Some(self.admission.body.admission_id.clone()),
                prepared_admission_id: None,
                accepted_at: ADMISSION_ISSUED_AT,
            },
            bond_backing_observed_at: None,
            penalty_gate: FindingAdmissionPenaltyGate::Ungoverned,
            collateral_authority: &self.collateral_key,
            constituent_expiry_bounds: FindingConstituentExpiryBounds {
                finding: CONSTITUENT_EXPIRES_AT,
                listing: WINDOW_EXPIRES_AT,
                pricing_hint: WINDOW_EXPIRES_AT,
                seller_authorization: WINDOW_EXPIRES_AT,
                profile: WINDOW_EXPIRES_AT,
            },
        }
    }

    fn bindings(&self) -> AdmissionBindings {
        AdmissionBindings {
            listing_envelope_sha256: self.listing_sha256.clone(),
            pricing_hint_envelope_sha256: self.hint_sha256.clone(),
            terms_envelope_sha256: self.terms_sha256.clone(),
            backing_envelope_sha256: self.backing_sha256.clone(),
            backing_allocation_id: self.backing.body.allocation_id.clone(),
            fee_schedule_envelope_sha256: self.schedule_sha256.clone(),
            issued_at: ADMISSION_ISSUED_AT,
            expires_at: ADMISSION_EXPIRES_AT,
        }
    }
}

fn finding_namespace(operator: &Keypair) -> GenericNamespaceOwnership {
    GenericNamespaceOwnership {
        namespace: "https://registry.seller.example".to_string(),
        owner_id: "seller-operator".to_string(),
        owner_name: Some("Seller Operator".to_string()),
        registry_url: "https://registry.seller.example".to_string(),
        signer_public_key: operator.public_key(),
        registered_at: 1,
        transferred_from_owner_id: None,
    }
}

fn signed_finding_listing(operator: &Keypair, finding: &Finding) -> SignedGenericListing {
    let body = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: FINDING_LISTING_ID.to_string(),
        namespace: "https://registry.seller.example".to_string(),
        published_at: ADMISSION_ISSUED_AT,
        expires_at: Some(WINDOW_EXPIRES_AT),
        status: GenericListingStatus::Active,
        namespace_ownership: finding_namespace(operator),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: FINDING_SERVER_ID.to_string(),
            display_name: Some("Finding server".to_string()),
            metadata_url: Some(format!(
                "https://registry.seller.example/finding/{}",
                finding.finding_id
            )),
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: format!("artifact-{FINDING_LISTING_ID}"),
            source_artifact_sha256: format!("sha-{FINDING_LISTING_ID}"),
        },
        boundary: GenericListingBoundary::default(),
    };
    SignedGenericListing::sign(body, operator).test_expect("sign finding listing")
}

fn finding_listing_entry(
    operator: &Keypair,
    finding: &Finding,
    capability_scope: &str,
    price_units: u64,
) -> Listing {
    Listing {
        rank: 1,
        listing: signed_finding_listing(operator, finding),
        pricing: SignedListingPricingHint::sign(
            ListingPricingHint {
                schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
                listing_id: FINDING_LISTING_ID.to_string(),
                namespace: "https://registry.seller.example".to_string(),
                provider_operator_id: "seller-operator".to_string(),
                capability_scope: capability_scope.to_string(),
                price_per_call: usd(price_units),
                sla: ListingSla {
                    max_latency_ms: 200,
                    availability_bps: 9_995,
                    throughput_rps: 100,
                },
                revocation_rate_bps: 5,
                recent_receipts_volume: 2_500,
                issued_at: ADMISSION_ISSUED_AT,
                expires_at: WINDOW_EXPIRES_AT,
            },
            operator,
        )
        .test_expect("sign finding pricing hint"),
        publisher: GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: "seller-operator".to_string(),
            operator_name: Some("Seller Operator".to_string()),
            registry_url: "https://registry.seller.example".to_string(),
            upstream_registry_urls: Vec::new(),
        },
        freshness: GenericListingReplicaFreshness {
            state: GenericListingFreshnessState::Fresh,
            age_secs: 20,
            max_age_secs: 300,
            valid_until: WINDOW_EXPIRES_AT,
            generated_at: NOW,
        },
    }
}

fn finding_bid_request(finding: &Finding, max_price_units: u64) -> BidRequest {
    BidRequest {
        schema: BID_REQUEST_SCHEMA.to_string(),
        agent_id: "buyer-agent-7".to_string(),
        payout_destination: None,
        listing_id: FINDING_LISTING_ID.to_string(),
        max_price_per_call: usd(max_price_units),
        window_seconds: 3_600,
        requested_scope: RequestedScope {
            server_id: FINDING_SERVER_ID.to_string(),
            tool_name: "read_finding".to_string(),
            max_invocations: Some(1),
            capability_scope_prefix: format!("finding:{}", finding.finding_id),
        },
        issued_at: NOW,
    }
}

const FINDING_PHEROMONE_TREATY: &str = "treaty:cognition-market:discovery";
const FINDING_PHEROMONE_NOW_MS: u64 = NOW * 1_000;

fn finding_pheromone_policy() -> PheromoneScarcityPolicy {
    let mut policy = PheromoneScarcityPolicy {
        schema: PHEROMONE_SCARCITY_POLICY_SCHEMA.to_string(),
        policy_id: "policy:cognition-market:finding-hints".to_string(),
        reputation_epoch: 9,
        window_id: String::new(),
        window_start_unix_ms: FINDING_PHEROMONE_NOW_MS - 10_000,
        window_end_unix_ms: FINDING_PHEROMONE_NOW_MS + 10_000,
        token_capacity: 100,
        newcomer_horizon_epochs: 8,
        treaty_scope: vec![FINDING_PHEROMONE_TREATY.to_string()],
        subject_class_namespace: FINDING_PHEROMONE_SUBJECT_NAMESPACE.to_string(),
        subject_class: FINDING_PHEROMONE_SUBJECT_CLASS.to_string(),
        observation_cost_verification: ObservationCostVerificationMode::Required,
        verifier_id: "did:chio:finding-cost-verifier".to_string(),
        runtime_policy_sha256: hex64('d'),
        policy_sha256: String::new(),
        active_peers_epoch: 9,
    };
    policy.window_id =
        scarcity_window_id(&policy, FINDING_PHEROMONE_TREATY).test_expect("window id");
    policy.policy_sha256 = scarcity_policy_sha256(&policy).test_expect("scarcity policy digest");
    policy
}

fn finding_pheromone_context(passport: &Keypair, kernel: &Keypair) -> PheromoneValidationContext {
    let verifier = keypair(84);
    let root_issuer = keypair(85);
    let root_body = PheromoneObservationCostVerifierRootBody {
        schema: PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA.to_string(),
        verifier_id: "did:chio:finding-cost-verifier".to_string(),
        verifier_key_id: "finding-cost-key-1".to_string(),
        public_key: verifier.public_key(),
        signature_algorithm: SigningAlgorithm::Ed25519,
        valid_from_unix_ms: FINDING_PHEROMONE_NOW_MS - 100_000,
        valid_until_unix_ms: FINDING_PHEROMONE_NOW_MS + 100_000,
        allowed_treaties: vec![FINDING_PHEROMONE_TREATY.to_string()],
        allowed_subject_class_namespaces: vec![FINDING_PHEROMONE_SUBJECT_NAMESPACE.to_string()],
        allowed_subject_classes: vec![FINDING_PHEROMONE_SUBJECT_CLASS.to_string()],
        runtime_policy_sha256: hex64('d'),
        issuer_kernel_id: "did:chio:receiver-runtime".to_string(),
    };
    let root = PheromoneObservationCostVerifierRoot {
        issuer_signature: root_issuer
            .sign(&canonical_json_bytes(&root_body).test_expect("canonical observation cost root")),
        body: root_body,
    };
    let trust_floor = PheromoneRuntimeTrustFloorState {
        entries: vec![PheromoneRuntimeTrustFloorEntry {
            verifier_id: root.body.verifier_id.clone(),
            key_id: root.body.verifier_key_id.clone(),
            highest_version: 1,
            latest_bundle_sha256: sha256_hex(b"finding-cost-verifier-bundle:v1"),
            latest_revocation_checkpoint_sha256: sha256_hex(b"finding-cost-verifier-revocation:v1"),
        }],
        ..PheromoneRuntimeTrustFloorState::default()
    };
    PheromoneValidationContext {
        now_unix_ms: FINDING_PHEROMONE_NOW_MS,
        replay_window_ms: 20_000,
        active_peers_in_treaty: 16,
        active_reputation_epoch: 9,
        known_reputation_epochs: vec![9],
        passports: vec![PassportAdmission {
            kernel_id: "did:chio:buyer-kernel".to_string(),
            public_key: passport.public_key(),
            valid_from_unix_ms: FINDING_PHEROMONE_NOW_MS - 100_000,
            valid_until_unix_ms: FINDING_PHEROMONE_NOW_MS + 100_000,
            first_seen_epoch: 1,
            revoked: false,
        }],
        kernel_public_keys: vec![kernel.public_key()],
        subject_classes: vec![finding_pheromone_subject_policy(FINDING_PHEROMONE_TREATY)],
        max_deposits_per_pair: 10,
        scarcity_policies: vec![finding_pheromone_policy()],
        runtime_policy_sha256: Some(hex64('d')),
        runtime_policy_issuer_public_keys: vec![root_issuer.public_key()],
        observation_cost_verifier_roots: vec![root],
        runtime_trust_floor_state: trust_floor,
    }
}

fn finding_pheromone_deposit(
    web: &Web,
    listing: &Listing,
    passport: &Keypair,
    nonce: &str,
    cost: u64,
) -> PheromoneDeposit {
    let admission_sha256 =
        signed_envelope_sha256(&web.admission).test_expect("admission envelope digest");
    let indicator = FindingPheromoneIndicator {
        schema: FINDING_PHEROMONE_INDICATOR_SCHEMA_V1.to_string(),
        finding_id: web.finding.finding_id.clone(),
        listing_id: listing.listing_id().to_string(),
        listing_envelope_sha256: signed_envelope_sha256(&listing.listing)
            .test_expect("listing envelope digest"),
        admission_envelope_sha256: admission_sha256,
        capability_scope: format!("finding:{}", web.finding.finding_id),
    };
    let body = PheromoneDepositBody {
        schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
        kernel_id: "did:chio:buyer-kernel".to_string(),
        agent_passport_key_hash: agent_passport_key_hash(&passport.public_key()),
        agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&passport.public_key()),
        subject_class: FINDING_PHEROMONE_SUBJECT_CLASS.to_string(),
        subject_class_namespace: FINDING_PHEROMONE_SUBJECT_NAMESPACE.to_string(),
        indicator: serde_json::to_value(indicator).test_expect("serialize indicator"),
        severity: Severity::Medium,
        confidence: FINDING_PHEROMONE_CONFIDENCE,
        timestamp_unix_ms: FINDING_PHEROMONE_NOW_MS - 1_000,
        decay_half_life_secs: FINDING_PHEROMONE_DECAY_HALF_LIFE_SECS,
        evaporation_floor: Some(FINDING_PHEROMONE_EVAPORATION_FLOOR),
        nonce: nonce.to_string(),
        treaty_scope: vec![FINDING_PHEROMONE_TREATY.to_string()],
        cost_commitment: None,
        workflow_context: None,
    };
    let mut deposit = sign_deposit(body, passport).test_expect("sign finding pheromone");
    let policy = finding_pheromone_policy();
    let deposit_body_sha256 = {
        let mut body = deposit.body.clone();
        body.cost_commitment = None;
        sha256_hex(&canonical_json_bytes(&body).test_expect("canonical deposit body"))
    };
    let deposit_signature_sha256 = sha256_hex(deposit.signature.to_hex().as_bytes());
    let observation_cost = PheromoneObservationCostAmount {
        unit: OBSERVATION_COST_UNIT.to_string(),
        amount: cost,
    };
    let leaf = PheromoneObservationCostLeaf {
        schema: PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA.to_string(),
        deposit_body_sha256,
        deposit_signature_sha256,
        kernel_id: deposit.body.kernel_id.clone(),
        agent_passport_key_hash: deposit.body.agent_passport_key_hash.clone(),
        treaty_id: FINDING_PHEROMONE_TREATY.to_string(),
        subject_class_namespace: FINDING_PHEROMONE_SUBJECT_NAMESPACE.to_string(),
        subject_class: FINDING_PHEROMONE_SUBJECT_CLASS.to_string(),
        observed_at_unix_ms: FINDING_PHEROMONE_NOW_MS - 500,
        event_digest_sha256: sha256_hex(nonce.as_bytes()),
        cost: observation_cost.clone(),
        scarcity_policy_sha256: policy.policy_sha256.clone(),
        runtime_policy_sha256: hex64('d'),
    };
    let leaf_bytes = canonical_json_bytes(&leaf).test_expect("canonical observation cost leaf");
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&leaf_bytes))
        .test_expect("build observation cost tree");
    let statement = PheromoneObservationCostStatement {
        schema: PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA.to_string(),
        commitment_id: format!("cost:{nonce}"),
        verifier_id: "did:chio:finding-cost-verifier".to_string(),
        verifier_key_id: "finding-cost-key-1".to_string(),
        runtime_policy_sha256: hex64('d'),
        scarcity_policy_sha256: leaf.scarcity_policy_sha256.clone(),
        deposit_body_sha256: leaf.deposit_body_sha256.clone(),
        deposit_signature_sha256: leaf.deposit_signature_sha256.clone(),
        kernel_id: leaf.kernel_id.clone(),
        agent_passport_key_hash: leaf.agent_passport_key_hash.clone(),
        treaty_id: leaf.treaty_id.clone(),
        subject_class_namespace: leaf.subject_class_namespace.clone(),
        subject_class: leaf.subject_class.clone(),
        observation_window_start_unix_ms: policy.window_start_unix_ms,
        observation_window_end_unix_ms: policy.window_end_unix_ms,
        observed_at_unix_ms: leaf.observed_at_unix_ms,
        event_digest_sha256: leaf.event_digest_sha256.clone(),
        cost: observation_cost,
        telemetry: PheromoneObservationCostTelemetryRoot {
            schema: PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA.to_string(),
            algorithm: OBSERVATION_COST_TELEMETRY_ALGORITHM.to_string(),
            root_hash: tree.root(),
            tree_size: 1,
            verifier_id: "did:chio:finding-cost-verifier".to_string(),
            verifier_key_id: "finding-cost-key-1".to_string(),
            closed_at_unix_ms: FINDING_PHEROMONE_NOW_MS,
        },
        inclusion_proof: tree
            .inclusion_proof(0)
            .test_expect("observation cost inclusion proof"),
        leaf_preimage_sha256: sha256_hex(&leaf_bytes),
    };
    let signature =
        keypair(84).sign(&canonical_json_bytes(&statement).test_expect("canonical cost statement"));
    deposit.body.cost_commitment = Some(PheromoneCostCommitment {
        schema: PHEROMONE_COST_COMMITMENT_SCHEMA.to_string(),
        statement,
        signature,
    });
    deposit
}

fn finding_pheromone_convention() -> FindingPheromoneConvention {
    FindingPheromoneConvention {
        treaty_id: FINDING_PHEROMONE_TREATY.to_string(),
        max_observation_cost_microunits: 125,
    }
}

#[test]
fn admitted_finding_clears_the_real_bid_path() {
    with_fiscal(|resolver| {
        let web = base_web();
        let context = web.context(resolver);
        let witness =
            verify_finding_admission(&web.admission, &context).test_expect("admission verifies");
        let expected_scope = format!("finding:{}", web.finding.finding_id);
        assert_eq!(witness.finding_id(), web.finding.finding_id);
        assert_eq!(witness.listing_id(), FINDING_LISTING_ID);
        assert_eq!(witness.capability_scope(), expected_scope);
        assert_eq!(witness.expires_at(), ADMISSION_EXPIRES_AT);
        assert_eq!(witness.admission().venue_id, VENUE_ID);

        let agent = keypair(31);
        let listing = finding_listing_entry(&web.operator, &web.finding, &expected_scope, 900);
        assert_eq!(listing.pricing.body.capability_scope, expected_scope);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign finding bid");
        let ask = bid_with_finding_admission(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &web.operator,
                agent_subject: agent.public_key(),
                token_id: "finding-token-0001".to_string(),
                now: NOW,
                grant_constraints: Vec::new(),
                dpop_required: None,
            },
            &witness,
        )
        .test_expect("admitted finding bid clears the marketplace path");

        assert_eq!(ask.body.listing_id, FINDING_LISTING_ID);
        assert_eq!(ask.body.quoted_price.units, 900);
        let grant = &ask.body.token_offer.scope.grants[0];
        assert_eq!(grant.server_id, FINDING_SERVER_ID);
        assert_eq!(grant.tool_name, "read_finding");
        assert_eq!(grant.max_invocations, Some(1));
        assert_eq!(grant.max_total_cost, Some(usd(900)));
    });
}

#[test]
fn finding_pheromone_positive_hint_re_resolves_current_listing_without_purchase_authority() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let deposit = finding_pheromone_deposit(&web, &listing, &passport, "hint-positive", 125);
        let substrate = InMemoryPheromoneSubstrate::new();
        let resolved = admit_and_resolve_finding_pheromone_hint(
            &substrate,
            deposit,
            &finding_pheromone_context(&passport, &kernel),
            &finding_pheromone_convention(),
            &listing,
            &web.admission,
            &web.context(resolver),
        )
        .test_expect("fully admit and resolve finding pheromone");
        assert_eq!(resolved.indicator.finding_id, web.finding.finding_id);
        assert_eq!(resolved.admission.listing_id(), FINDING_LISTING_ID);
        assert!(!resolved.grants_purchase_authority());
    });
}

#[test]
fn finding_pheromone_rejects_stale_unadmitted_wrong_signer_and_wrong_passport() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let wrong = keypair(83);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );

        let mut stale = finding_pheromone_deposit(&web, &listing, &passport, "hint-stale", 125);
        stale.body.timestamp_unix_ms = FINDING_PHEROMONE_NOW_MS - 20_000;
        stale = sign_deposit(stale.body, &passport).test_expect("re-sign stale hint");
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                stale,
                &finding_pheromone_context(&passport, &kernel),
                &finding_pheromone_convention(),
                &listing,
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Deposit(_))
        ));

        let unadmitted =
            finding_pheromone_deposit(&web, &listing, &passport, "hint-unadmitted", 125);
        let mut unadmitted_context = finding_pheromone_context(&passport, &kernel);
        unadmitted_context.passports.clear();
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                unadmitted,
                &unadmitted_context,
                &finding_pheromone_convention(),
                &listing,
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Deposit(_))
        ));

        let valid = finding_pheromone_deposit(&web, &listing, &passport, "hint-signer", 125);
        let wrong_signer =
            sign_deposit(valid.body.clone(), &wrong).test_expect("wrong signer hint");
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                wrong_signer,
                &finding_pheromone_context(&passport, &kernel),
                &finding_pheromone_convention(),
                &listing,
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Deposit(_))
        ));

        let mut wrong_passport = valid.body;
        wrong_passport.agent_passport_key_hash = hex64('f');
        let wrong_passport =
            sign_deposit(wrong_passport, &passport).test_expect("wrong passport hint");
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                wrong_passport,
                &finding_pheromone_context(&passport, &kernel),
                &finding_pheromone_convention(),
                &listing,
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Deposit(_))
        ));
    });
}

#[test]
fn finding_pheromone_rejects_wrong_scope_replay_and_over_cost() {
    with_fiscal(|resolver| {
        let web = base_web();
        let passport = keypair(81);
        let kernel = keypair(82);
        let listing = finding_listing_entry(
            &web.operator,
            &web.finding,
            &format!("finding:{}", web.finding.finding_id),
            900,
        );
        let context = finding_pheromone_context(&passport, &kernel);
        let convention = finding_pheromone_convention();

        let mut wrong_scope =
            finding_pheromone_deposit(&web, &listing, &passport, "hint-scope", 125);
        wrong_scope.body.treaty_scope = vec!["treaty:other".to_string()];
        wrong_scope = sign_deposit(wrong_scope.body, &passport).test_expect("re-sign scope hint");
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                wrong_scope,
                &context,
                &convention,
                &listing,
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Convention(_))
        ));

        let over_cost = finding_pheromone_deposit(&web, &listing, &passport, "hint-over-cost", 126);
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &InMemoryPheromoneSubstrate::new(),
                over_cost,
                &context,
                &convention,
                &listing,
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::ObservationCostExceeded)
        ));

        let replay = finding_pheromone_deposit(&web, &listing, &passport, "hint-replay", 125);
        let substrate = InMemoryPheromoneSubstrate::new();
        admit_and_resolve_finding_pheromone_hint(
            &substrate,
            replay.clone(),
            &context,
            &convention,
            &listing,
            &web.admission,
            &web.context(resolver),
        )
        .test_expect("first hint admission");
        assert!(matches!(
            admit_and_resolve_finding_pheromone_hint(
                &substrate,
                replay,
                &context,
                &convention,
                &listing,
                &web.admission,
                &web.context(resolver),
            ),
            Err(FindingPheromoneError::Deposit(_))
        ));
    });
}

#[test]
fn wrong_venue_key_rejects() {
    with_fiscal(|resolver| {
        let mut web = base_web();
        web.venue_key = keypair(9).public_key();
        let context = web.context(resolver);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(
            error,
            FindingAdmissionError::AdmissionEnvelope(FindingError::AuthorityMismatch("admission"))
        );
    });
}

#[test]
fn expired_admission_rejects() {
    with_fiscal(|resolver| {
        let web = base_web();
        let mut context = web.context(resolver);
        context.now = ADMISSION_EXPIRES_AT;
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::AdmissionExpired);
    });
}

#[test]
fn future_issued_admission_rejects() {
    with_fiscal(|resolver| {
        let web = base_web();
        let mut context = web.context(resolver);
        context.now = ADMISSION_ISSUED_AT - 1;
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::AdmissionNotYetLive);
    });
}

#[test]
fn terms_digest_mismatch_rejects() {
    with_fiscal(|resolver| {
        let mut web = base_web();
        let mut bindings = web.bindings();
        bindings.terms_envelope_sha256 = hex64('f');
        web.admission = signed_admission(&web.venue, &web.finding, &bindings);
        let context = web.context(resolver);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::TermsDigestMismatch);
    });
}

#[test]
fn terms_identity_must_match_every_admission_binding() {
    enum TermsBinding {
        FindingId,
        FindingArtifact,
        ListingId,
        VerifierProfile,
    }

    with_fiscal(|resolver| {
        for (mismatch, binding) in [
            ("finding id", TermsBinding::FindingId),
            ("finding artifact", TermsBinding::FindingArtifact),
            ("listing id", TermsBinding::ListingId),
            ("verifier profile", TermsBinding::VerifierProfile),
        ] {
            let mut web = base_web();
            let mut terms = web.terms.body.clone();
            match binding {
                TermsBinding::FindingId => terms.finding_id = hex64('f'),
                TermsBinding::FindingArtifact => terms.finding_artifact_sha256 = hex64('f'),
                TermsBinding::ListingId => terms.listing_id = "listing-other".to_string(),
                TermsBinding::VerifierProfile => {
                    terms.verifier_profile_envelope_sha256 = hex64('e');
                }
            }
            terms.terms_id = String::new();
            terms.terms_id = compute_terms_id(&terms).test_expect("mismatched terms id");
            web.terms = SignedFindingMarketTerms::sign(terms, &web.seller)
                .test_expect("sign mismatched terms");
            web.terms_sha256 =
                signed_envelope_sha256(&web.terms).test_expect("mismatched terms digest");
            let bindings = web.bindings();
            web.admission = signed_admission(&web.venue, &web.finding, &bindings);

            assert_eq!(
                verify_finding_admission(&web.admission, &web.context(resolver)).err(),
                Some(FindingAdmissionError::TermsIdentityMismatch),
                "{mismatch} mismatch must deny"
            );
        }
    });
}

#[test]
fn backing_digest_mismatch_rejects() {
    with_fiscal(|resolver| {
        let mut web = base_web();
        let mut bindings = web.bindings();
        bindings.backing_envelope_sha256 = hex64('f');
        web.admission = signed_admission(&web.venue, &web.finding, &bindings);
        let context = web.context(resolver);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::BackingDigestMismatch);
    });
}

#[test]
fn consumed_allocation_must_name_the_active_admission() {
    with_fiscal(|resolver| {
        let web = base_web();
        let mut context = web.context(resolver);
        context.allocation_snapshot.active_admission_id = None;
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(
            error,
            FindingAdmissionError::AdmissionNotActiveForAllocation
        );

        context.allocation_snapshot.active_admission_id = Some(hex64('f'));
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(
            error,
            FindingAdmissionError::AdmissionNotActiveForAllocation
        );
    });
}

#[test]
fn activation_and_current_admission_require_distinct_allocation_states() {
    with_fiscal(|resolver| {
        let web = base_web();
        let mut context = web.context(resolver);

        // The post-transaction state is consumed by this exact active
        // admission, so it produces the bid witness.
        verify_finding_admission(&web.admission, &context)
            .test_expect("consumed allocation backs the active admission");
        assert_eq!(
            verify_finding_admission_for_activation(&web.admission, &context).err(),
            Some(FindingAdmissionError::AllocationUnavailableForActivation)
        );

        // A byte-identical durable prepare replay still owns the consumed
        // allocation, but it is not yet an active admission and cannot
        // produce a bid witness.
        context.allocation_snapshot.active_admission_id = None;
        context.allocation_snapshot.prepared_admission_id =
            Some(web.admission.body.admission_id.clone());
        verify_finding_admission_for_activation(&web.admission, &context)
            .test_expect("exact prepared replay may resume activation");
        assert_eq!(
            verify_finding_admission(&web.admission, &context).err(),
            Some(FindingAdmissionError::AdmissionNotActiveForAllocation)
        );

        context.allocation_snapshot.prepared_admission_id = Some(hex64('f'));
        assert_eq!(
            verify_finding_admission_for_activation(&web.admission, &context).err(),
            Some(FindingAdmissionError::AllocationUnavailableForActivation)
        );

        // Before the transaction the same exact allocation is available
        // and unbound. It may pass activation validation but cannot
        // produce a spendable admission witness.
        context.allocation_snapshot.status = FindingAllocationStatus::Available;
        context.allocation_snapshot.active_admission_id = None;
        context.allocation_snapshot.prepared_admission_id = None;
        verify_finding_admission_for_activation(&web.admission, &context)
            .test_expect("available allocation may enter activation");
        assert_eq!(
            verify_finding_admission(&web.admission, &context).err(),
            Some(FindingAdmissionError::AdmissionNotActiveForAllocation)
        );
    });
}

#[test]
fn expired_released_or_mismatched_allocation_snapshot_rejects() {
    with_fiscal(|resolver| {
        let web = base_web();
        let mut context = web.context(resolver);
        context.allocation_snapshot.status = FindingAllocationStatus::Expired;
        assert_eq!(
            verify_finding_admission(&web.admission, &context).err(),
            Some(FindingAdmissionError::AllocationExpired)
        );

        context = web.context(resolver);
        context.allocation_snapshot.status = FindingAllocationStatus::Released;
        assert_eq!(
            verify_finding_admission(&web.admission, &context).err(),
            Some(FindingAdmissionError::AllocationReleased)
        );

        context = web.context(resolver);
        context.allocation_snapshot.backing_envelope_sha256 = hex64('f');
        assert_eq!(
            verify_finding_admission(&web.admission, &context).err(),
            Some(FindingAdmissionError::AllocationSnapshotMismatch)
        );
    });
}

#[test]
fn bond_backing_observed_before_the_allocation_rejects() {
    with_fiscal(|resolver| {
        let web = base_web();
        // Observed at the same instant the allocation was registered: the
        // observation cannot have seen this collateral.
        let mut context = web.context(resolver);
        context.bond_backing_observed_at = Some(context.allocation_snapshot.accepted_at);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(
            error,
            FindingAdmissionError::BondObservationBeforeAllocation
        );

        // Observed strictly after registration: the ordering holds.
        let mut context = web.context(resolver);
        context.bond_backing_observed_at = Some(context.allocation_snapshot.accepted_at + 1);
        verify_finding_admission(&web.admission, &context).test_expect("ordered observation");

        // No affirmative bond claim carries no ordering obligation.
        let context = web.context(resolver);
        assert!(context.bond_backing_observed_at.is_none());
        verify_finding_admission(&web.admission, &context).test_expect("no bond claim");
    });
}

/// A penalty evaluation over the named listing, shaped by the caller.
fn penalty_evaluation_for(listing_id: &str) -> OpenMarketPenaltyEvaluation {
    OpenMarketPenaltyEvaluation {
        listing_id: listing_id.to_string(),
        namespace: "https://registry.seller.example".to_string(),
        fee_schedule_id: "fee-schedule-01".to_string(),
        charter_id: "charter-01".to_string(),
        case_id: "case-01".to_string(),
        penalty_id: "penalty-01".to_string(),
        governing_operator_id: "governing-operator".to_string(),
        action: OpenMarketPenaltyAction::SlashBond,
        state: OpenMarketPenaltyState::Enforced,
        effective_state: OpenMarketPenaltyEffectiveState::BondSlashed,
        evaluated_at: NOW,
        publication_fee: None,
        dispute_fee: None,
        market_participation_fee: None,
        bond_requirement: None,
        blocks_admission: true,
        findings: Vec::new(),
    }
}

#[test]
fn blocking_penalty_evaluation_rejects_admission() {
    with_fiscal(|resolver| {
        let web = base_web();
        let evaluation = penalty_evaluation_for(&web.admission.body.listing_id);
        let mut context = web.context(resolver);
        context.penalty_gate = FindingAdmissionPenaltyGate::Evaluated(&evaluation);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::AdmissionBlockedByPenalty);
    });
}

#[test]
fn penalty_evaluation_for_another_listing_rejects_admission() {
    with_fiscal(|resolver| {
        let web = base_web();
        // A clear evaluation, but over some other listing: it says nothing
        // about the one being admitted, so it must not stand in for it.
        let mut evaluation = penalty_evaluation_for("listing-elsewhere-0001");
        evaluation.state = OpenMarketPenaltyState::Reversed;
        evaluation.effective_state = OpenMarketPenaltyEffectiveState::Reversed;
        evaluation.blocks_admission = false;
        let mut context = web.context(resolver);
        context.penalty_gate = FindingAdmissionPenaltyGate::Evaluated(&evaluation);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::PenaltyEvaluationMismatch);
    });
}

#[test]
fn unresolved_penalty_evaluation_rejects_admission() {
    with_fiscal(|resolver| {
        let web = base_web();
        // An evaluation that failed carries findings and no blocking
        // verdict; it establishes nothing, so it admits nothing.
        let mut evaluation = penalty_evaluation_for(&web.admission.body.listing_id);
        evaluation.blocks_admission = false;
        evaluation.findings = vec![OpenMarketFinding {
            code: OpenMarketFindingCode::PenaltyUnverifiable,
            message: "penalty envelope did not verify".to_string(),
        }];
        let mut context = web.context(resolver);
        context.penalty_gate = FindingAdmissionPenaltyGate::Evaluated(&evaluation);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::PenaltyEvaluationUnresolved);
    });
}

#[test]
fn clear_penalty_evaluation_admits() {
    with_fiscal(|resolver| {
        let web = base_web();
        // A reversed penalty no longer blocks, so the same gate that
        // refuses an enforced one must admit here.
        let mut evaluation = penalty_evaluation_for(&web.admission.body.listing_id);
        evaluation.action = OpenMarketPenaltyAction::ReverseSlash;
        evaluation.state = OpenMarketPenaltyState::Reversed;
        evaluation.effective_state = OpenMarketPenaltyEffectiveState::Reversed;
        evaluation.blocks_admission = false;
        let mut context = web.context(resolver);
        context.penalty_gate = FindingAdmissionPenaltyGate::Evaluated(&evaluation);
        verify_finding_admission(&web.admission, &context).test_expect("clear penalty state");
    });
}

#[test]
fn undersized_listing_requirement_rejects() {
    with_fiscal(|resolver| {
        let web = web_with_schedule(STAKE_UNITS + EXPOSURE_UNITS - 1, true, "USD");
        let context = web.context(resolver);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::ListingRequirementUndersized);
    });
}

#[test]
fn non_slashable_listing_requirement_rejects() {
    with_fiscal(|resolver| {
        let web = web_with_schedule(REQUIREMENT_UNITS, false, "USD");
        let context = web.context(resolver);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::ListingRequirementNotSlashable);
    });
}

#[test]
fn wrong_currency_requirement_rejects() {
    with_fiscal(|resolver| {
        let web = web_with_schedule(REQUIREMENT_UNITS, true, "EUR");
        let context = web.context(resolver);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::CurrencyMismatch);
    });
}

#[test]
fn admission_expiry_past_a_constituent_rejects() {
    with_fiscal(|resolver| {
        // Caller-resolved finding bound.
        let web = base_web();
        let mut context = web.context(resolver);
        context.constituent_expiry_bounds.finding = ADMISSION_EXPIRES_AT - 1;
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(
            error,
            FindingAdmissionError::ExpiryBeyondConstituent("finding")
        );

        // A terms window shorter than the admission window.
        let mut web = base_web();
        web.terms = signed_terms(&web.seller, &web.finding, ADMISSION_EXPIRES_AT - 1);
        web.terms_sha256 = signed_envelope_sha256(&web.terms).test_expect("short terms digest");
        let bindings = web.bindings();
        web.admission = signed_admission(&web.venue, &web.finding, &bindings);
        let context = web.context(resolver);
        let error = verify_finding_admission(&web.admission, &context).test_unwrap_err();
        assert_eq!(
            error,
            FindingAdmissionError::ExpiryBeyondConstituent("terms")
        );
    });
}

#[test]
fn scope_mismatch_at_bid_time_rejects() {
    with_fiscal(|resolver| {
        let web = base_web();
        let context = web.context(resolver);
        let witness =
            verify_finding_admission(&web.admission, &context).test_expect("admission verifies");

        let agent = keypair(31);
        let other_scope = format!("finding:{}", hex64('f'));
        let listing = finding_listing_entry(&web.operator, &web.finding, &other_scope, 900);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign finding bid");
        let error = bid_with_finding_admission(
            &request,
            BidMintContext {
                listing: &listing,
                issuer_keypair: &web.operator,
                agent_subject: agent.public_key(),
                token_id: "finding-token-0002".to_string(),
                now: NOW,
                grant_constraints: Vec::new(),
                dpop_required: None,
            },
            &witness,
        )
        .test_unwrap_err();
        assert_eq!(error, FindingAdmissionError::ScopeMismatch);
    });
}

#[test]
fn bid_rejects_a_listing_the_admission_was_not_issued_for() {
    with_fiscal(|resolver| {
        let web = web_with_schedule(REQUIREMENT_UNITS, true, "USD");
        let agent = keypair(31);
        let expected_scope = format!("finding:{}", web.finding.finding_id);
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission verifies");

        // Same finding and the same advertised scope, but a different
        // listing envelope: scope equality alone would let this ride an
        // admission issued for another listing.
        let other_listing =
            finding_listing_entry(&web.operator, &web.finding, &expected_scope, 901);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 901), &agent)
            .test_expect("sign bid request");
        let outcome = bid_with_finding_admission(
            &request,
            BidMintContext {
                listing: &other_listing,
                issuer_keypair: &web.operator,
                agent_subject: agent.public_key(),
                token_id: "finding-token-0002".to_string(),
                now: NOW,
                grant_constraints: Vec::new(),
                dpop_required: None,
            },
            &witness,
        );
        assert_eq!(
            outcome.err(),
            Some(FindingAdmissionError::PricingHintMismatch)
        );
    });
}

#[test]
fn backing_locked_below_the_promised_sum_rejects() {
    with_fiscal(|resolver| {
        let mut web = web_with_schedule(REQUIREMENT_UNITS, true, "USD");
        // The schedule requirement stays adequate; only the collateral
        // actually locked falls short of stake plus exposure.
        let underfunded = signed_backing_committing(
            &keypair(4),
            &web.seller,
            &web.finding,
            &web.schedule_sha256,
            STAKE_UNITS + EXPOSURE_UNITS - 1,
            &web.terms_sha256,
        );
        web.backing_sha256 = signed_envelope_sha256(&underfunded).test_expect("backing digest");
        web.backing = underfunded;
        let bindings = web.bindings();
        web.admission = signed_admission(&web.venue, &web.finding, &bindings);
        assert_eq!(
            verify_finding_admission(&web.admission, &web.context(resolver)).err(),
            Some(FindingAdmissionError::BackingUnderfunded)
        );
    });
}

#[test]
fn fee_schedule_digest_mismatch_rejects() {
    with_fiscal(|resolver| {
        let mut web = web_with_schedule(REQUIREMENT_UNITS, true, "USD");
        let mut bindings = web.bindings();
        bindings.fee_schedule_envelope_sha256 = hex64('9');
        web.admission = signed_admission(&web.venue, &web.finding, &bindings);
        assert_eq!(
            verify_finding_admission(&web.admission, &web.context(resolver)).err(),
            Some(FindingAdmissionError::FeeScheduleDigestMismatch)
        );
    });
}

#[test]
fn admission_expiry_is_bounded_by_every_constituent() {
    with_fiscal(|resolver| {
        for label in [
            "finding",
            "listing",
            "pricing_hint",
            "seller_authorization",
            "profile",
        ] {
            let web = web_with_schedule(REQUIREMENT_UNITS, true, "USD");
            let mut narrowed = web.context(resolver);
            let expires_at = ADMISSION_EXPIRES_AT - 1;
            match label {
                "finding" => narrowed.constituent_expiry_bounds.finding = expires_at,
                "listing" => narrowed.constituent_expiry_bounds.listing = expires_at,
                "pricing_hint" => narrowed.constituent_expiry_bounds.pricing_hint = expires_at,
                "seller_authorization" => {
                    narrowed.constituent_expiry_bounds.seller_authorization = expires_at;
                }
                "profile" => narrowed.constituent_expiry_bounds.profile = expires_at,
                _ => unreachable!(),
            }
            let outcome = verify_finding_admission(&web.admission, &narrowed);
            assert_eq!(
                outcome.err(),
                Some(FindingAdmissionError::ExpiryBeyondConstituent(label)),
                "bound {label} did not deny an over-long admission",
            );
        }

        for label in ["purchase_authority", "failed_delivery_authority"] {
            let mut web = web_with_schedule(REQUIREMENT_UNITS, true, "USD");
            let mut admission = web.admission.body.clone();
            match label {
                "purchase_authority" => {
                    admission.purchase_authority.valid_until = ADMISSION_EXPIRES_AT - 1;
                }
                "failed_delivery_authority" => {
                    admission.failed_delivery_authority.valid_until = ADMISSION_EXPIRES_AT - 1;
                }
                _ => unreachable!(),
            }
            admission.admission_id = compute_admission_id(&admission).test_expect("admission id");
            web.admission = SignedFindingAdmission::sign(admission, &web.venue)
                .test_expect("sign narrowed admission");
            let context = web.context(resolver);
            assert_eq!(
                verify_finding_admission(&web.admission, &context).err(),
                Some(FindingAdmissionError::ExpiryBeyondConstituent(label)),
                "bound {label} did not deny an over-long admission",
            );
        }

        let mut web = web_with_schedule(REQUIREMENT_UNITS, true, "USD");
        let mut backing = web.backing.body.clone();
        backing.expires_at = ADMISSION_EXPIRES_AT - 1;
        backing.allocation_id = compute_allocation_id(&backing).test_expect("allocation id");
        web.backing = SignedFindingBondBacking::sign(backing, &keypair(4))
            .test_expect("sign narrowed backing");
        web.backing_sha256 = signed_envelope_sha256(&web.backing).test_expect("backing digest");
        let mut admission = web.admission.body.clone();
        admission.backing_allocation_id = web.backing.body.allocation_id.clone();
        admission.backing_envelope_sha256 = web.backing_sha256.clone();
        admission.admission_id = compute_admission_id(&admission).test_expect("admission id");
        web.admission = SignedFindingAdmission::sign(admission, &web.venue)
            .test_expect("sign backing-bounded admission");
        let context = web.context(resolver);
        assert_eq!(
            verify_finding_admission(&web.admission, &context).err(),
            Some(FindingAdmissionError::ExpiryBeyondConstituent("backing"))
        );
    });
}

#[test]
fn backing_committing_other_terms_rejects() {
    with_fiscal(|resolver| {
        let mut web = web_with_schedule(REQUIREMENT_UNITS, true, "USD");
        // A well-formed allocation for this seller, finding, and listing
        // that was sized against different terms than the admission cites.
        let foreign = signed_backing_committing(
            &keypair(4),
            &web.seller,
            &web.finding,
            &web.schedule_sha256,
            LOCKED_UNITS,
            &hex64('f'),
        );
        web.backing_sha256 = signed_envelope_sha256(&foreign).test_expect("backing digest");
        web.backing = foreign;
        let bindings = web.bindings();
        web.admission = signed_admission(&web.venue, &web.finding, &bindings);
        assert_eq!(
            verify_finding_admission(&web.admission, &web.context(resolver)).err(),
            Some(FindingAdmissionError::BackingBindingMismatch)
        );
    });
}

fn purchase_mint_context<'a>(
    listing: &'a Listing,
    operator: &'a Keypair,
    agent: &Keypair,
) -> BidMintContext<'a> {
    BidMintContext {
        listing,
        issuer_keypair: operator,
        agent_subject: agent.public_key(),
        token_id: "finding-token-0002".to_string(),
        now: NOW,
        grant_constraints: Vec::new(),
        dpop_required: None,
    }
}

fn signed_purchase_ask(
    web: &Web,
    resolver: &FiscalResolver<'_>,
    agent: &Keypair,
    price_units: u64,
) -> chio_open_market::bidding::SignedAskResponse {
    let witness =
        verify_finding_admission(&web.admission, &web.context(resolver)).test_expect("admission");
    let expected_scope = format!("finding:{}", web.finding.finding_id);
    let listing = finding_listing_entry(&web.operator, &web.finding, &expected_scope, price_units);
    let request = SignedBidRequest::sign(finding_bid_request(&web.finding, price_units), agent)
        .test_expect("sign purchase bid");
    bid_with_finding_purchase(
        &request,
        purchase_mint_context(&listing, &web.operator, agent),
        &witness,
        &web.finding,
    )
    .test_expect("purchase mint")
}

#[test]
fn purchase_mint_authors_the_delivery_committed_grant() {
    with_fiscal(|resolver| {
        let web = base_web();
        let agent = keypair(31);
        let ask = signed_purchase_ask(&web, resolver, &agent, 900);

        let grant = &ask.body.token_offer.scope.grants[0];
        assert_eq!(grant.max_invocations, Some(1));
        assert_eq!(grant.dpop_required, Some(true));
        assert_eq!(grant.constraints.len(), 2);
        assert!(grant.constraints.iter().any(|constraint| matches!(
            constraint,
            chio_open_market::capability::scope::Constraint::OutputDigestSha256(digest)
                if digest == &web.finding.payload_sha256
        )));
        assert!(grant.constraints.iter().any(|constraint| matches!(
            constraint,
            chio_open_market::capability::scope::Constraint::RequireFindingPurchase(marker)
                if marker.finding_id == web.finding.finding_id
                    && marker.listing_id == FINDING_LISTING_ID
        )));
    });
}

#[test]
fn purchase_mint_rejects_a_preoccupied_context_and_bad_cardinality() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let expected_scope = format!("finding:{}", web.finding.finding_id);
        let listing = finding_listing_entry(&web.operator, &web.finding, &expected_scope, 900);
        let agent = keypair(31);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign purchase bid");

        let mut preoccupied = purchase_mint_context(&listing, &web.operator, &agent);
        preoccupied.dpop_required = Some(false);
        assert_eq!(
            bid_with_finding_purchase(&request, preoccupied, &witness, &web.finding).err(),
            Some(FindingAdmissionError::MintContextPreoccupied)
        );

        let mut multi = finding_bid_request(&web.finding, 900);
        multi.requested_scope.max_invocations = Some(2);
        let multi = SignedBidRequest::sign(multi, &agent).test_expect("sign multi bid");
        assert_eq!(
            bid_with_finding_purchase(
                &multi,
                purchase_mint_context(&listing, &web.operator, &agent),
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::InvocationCardinality)
        );
    });
}

#[test]
fn purchase_mint_rechecks_finding_liveness_at_the_mint_clock() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let expected_scope = format!("finding:{}", web.finding.finding_id);
        let listing = finding_listing_entry(&web.operator, &web.finding, &expected_scope, 900);
        let agent = keypair(31);
        let request = SignedBidRequest::sign(finding_bid_request(&web.finding, 900), &agent)
            .test_expect("sign purchase bid");

        for (mint_now, expected) in [
            (
                web.finding.issued_at - 1,
                FindingAdmissionError::FindingNotYetLive,
            ),
            (
                web.finding.expires_at,
                FindingAdmissionError::FindingExpired,
            ),
        ] {
            let mut context = purchase_mint_context(&listing, &web.operator, &agent);
            context.now = mint_now;
            let result = bid_with_finding_purchase(&request, context, &witness, &web.finding);
            assert_eq!(result.err(), Some(expected), "mint clock {mint_now}");
        }
    });
}

#[test]
fn purchase_accept_requires_exact_amounts_and_the_committed_profile() {
    with_fiscal(|resolver| {
        let web = base_web();
        let witness = verify_finding_admission(&web.admission, &web.context(resolver))
            .test_expect("admission");
        let agent = keypair(31);
        let ask = signed_purchase_ask(&web, resolver, &agent, 900);
        let reservation_authority = keypair(41);
        let sign_reservation = |units: u64| {
            let ask_digest = chio_open_market::crypto::sha256_hex(
                &chio_open_market::canonical_json_bytes(&ask.body).test_expect("ask bytes"),
            );
            let receipt = chio_open_market::bidding::ReservationReceipt {
                schema: chio_open_market::bidding::RESERVATION_RECEIPT_SCHEMA.to_string(),
                receipt_id: "reservation-0001".to_string(),
                agent_id: "buyer-agent-7".to_string(),
                listing_id: FINDING_LISTING_ID.to_string(),
                ask_digest,
                reserved_amount: usd(units),
            };
            let signed = chio_open_market::bidding::SignedReservationReceipt::sign(
                receipt,
                &reservation_authority,
            )
            .test_expect("sign reservation");
            chio_open_market::bidding::VerifiedReservationReceipt::from_signed(
                &signed,
                &reservation_authority.public_key(),
            )
            .test_expect("verify reservation")
        };

        let accepted = accept_finding_purchase(
            &ask,
            &sign_reservation(900),
            &agent,
            NOW + 60,
            &witness,
            &web.finding,
        )
        .test_expect("exact purchase accept");
        assert_eq!(accepted.body.quoted_price, usd(900));
        assert_eq!(accepted.body.bid_receipt_id, "reservation-0001");

        assert_eq!(
            accept_finding_purchase(
                &ask,
                &sign_reservation(1_000),
                &agent,
                NOW + 60,
                &witness,
                &web.finding,
            )
            .err(),
            Some(FindingAdmissionError::AmountMismatch),
            "an oversized reservation must not mask a mispriced purchase"
        );
    });
}
