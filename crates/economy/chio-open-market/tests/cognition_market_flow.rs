//! Spec-shaped coverage for the proposed agent cognition market
//! (research spike, branch `research/cognition-market`).
//!
//! Companion documents:
//! - `docs/research/agent-cognition-market.md` (design memo)
//! - `docs/research/cognition-market/ARCHITECTURE.md` (design set)
//! - `docs/adr/ADR-0017-cognition-market-finding-artifacts.md`
//!
//! Three of these tests pass today: the buy leg clears the REAL `bid()`
//! path for a finding listing (colon-segment scope semantics), the bid
//! shape needs zero new fields, and the elicitation ceiling is
//! deterministic. The `#[ignore]`d test specifies the desired end-to-end
//! reveal flow and names the seams that do not exist yet; run it with
//! `cargo test -- --ignored` to see the first missing seam. Nothing here
//! is production wiring.

use chio_open_market::{
    bidding::{
        bid, BidMintContext, BidRequest, RequestedScope, SignedBidRequest, ASK_RESPONSE_SCHEMA,
        BID_REQUEST_SCHEMA,
    },
    capability::scope::MonetaryAmount,
    crypto::Keypair,
    listing::{
        GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole, Listing,
        ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
        GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    },
};

use chio_test_support::prelude::*;

const FINDING_SERVER_ID: &str = "finding-server.seller.example";
const FINDING_LISTING_ID: &str = "listing-finding-dead-end-0001";

fn hex64(fill: char) -> String {
    std::iter::repeat_n(fill, 64).collect()
}

/// Colon-segment scope for one finding, per the real marketplace
/// semantics: `capability_scope_covers` splits on `:` and requires the
/// advertised scope to be a segment-prefix of the requested one
/// (`chio-open-market/src/bidding.rs:534`).
fn finding_scope() -> String {
    format!("finding:{}", hex64('a'))
}

/// Stub shapes mirroring the interface sketches in the memo (section 6.1).
/// They live in this test file on purpose: the production types do not
/// exist yet, and this spike must not add public API surface. Fields and
/// variants exist to specify the artifact shape, so dead-code analysis is
/// silenced for the module.
#[allow(dead_code)]
mod finding_stubs {
    pub const FINDING_SCHEMA_V1: &str = "chio.finding.v1";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FindingOutcomeClass {
        /// "Doing X fails / has no effect": the negative result.
        NullResult,
        /// "This change makes the committed check pass": the verified fix.
        VerifiedFix,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FindingGuaranteeClass {
        /// Claim re-checkable by deterministic re-execution of the
        /// committed descriptor (the coding-agent wedge).
        DeterministicReplay,
        /// Execution, cost, and output digest attested by mediated
        /// receipts; claim semantics not re-checkable.
        MeteredAttested,
    }

    #[derive(Debug, Clone)]
    pub struct FindingDescriptor {
        pub topic: String,
        pub context_sha256: String,
        pub outcome_class: FindingOutcomeClass,
    }

    #[derive(Debug, Clone)]
    pub struct Finding {
        pub schema: String,
        pub finding_id: String,
        pub descriptor: FindingDescriptor,
        pub guarantee_class: FindingGuaranteeClass,
        /// Commitment to the reveal: digest of the canonical reveal
        /// envelope {media_type, payload_b64}. The envelope deliberately
        /// excludes finding_id so the commitment and the content-addressed
        /// id do not form a hash cycle (ARCHITECTURE 4.5).
        pub payload_sha256: String,
        pub evidence_receipt_ids: Vec<String>,
        pub evidence_cost_units: u64,
        pub bond_ref: String,
        pub status_feed_ref: String,
    }

    /// Delivery proof the reveal step must produce: a kernel receipt whose
    /// `content_hash` equals the finding's committed `payload_sha256`.
    /// Today no tool contract enforces that equality, so this stub can
    /// only report the seam as missing.
    pub fn mediated_reveal_delivery_receipt(_finding: &Finding) -> Option<String> {
        None
    }

    /// Elicitation ceiling from memo section 6.6: the counterfactual the
    /// platform can actually meter (re-derivation quote) discounted by the
    /// planner-owned priors, hard-capped by the purchasing allocation.
    /// Deterministic and implementable today; kept here as spec.
    pub struct FindingBidBasis {
        pub rederivation_quote_units: u64,
        pub would_have_run_bps: u16,
        pub sibling_redundancy_bps: u16,
        pub guarantee_class_bps: u16,
        pub budget_remaining_units: u64,
    }

    pub fn finding_bid_ceiling(basis: &FindingBidBasis) -> u64 {
        const BPS: u128 = 10_000;
        let would = u128::from(basis.would_have_run_bps.min(10_000));
        let keep = BPS - u128::from(basis.sibling_redundancy_bps.min(10_000));
        let class = u128::from(basis.guarantee_class_bps.min(10_000));
        let discounted =
            u128::from(basis.rederivation_quote_units) * would / BPS * keep / BPS * class / BPS;
        u64::try_from(discounted)
            .unwrap_or(u64::MAX)
            .min(basis.budget_remaining_units)
    }
}

use finding_stubs::{
    finding_bid_ceiling, mediated_reveal_delivery_receipt, Finding, FindingBidBasis,
    FindingDescriptor, FindingGuaranteeClass, FindingOutcomeClass, FINDING_SCHEMA_V1,
};

fn sealed_negative_result() -> Finding {
    Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: hex64('f'),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#flaky-suite-investigation".to_string(),
            context_sha256: hex64('a'),
            outcome_class: FindingOutcomeClass::NullResult,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: hex64('b'),
        evidence_receipt_ids: vec!["receipt-0001".to_string(), "receipt-0002".to_string()],
        evidence_cost_units: 4_200,
        bond_ref: "bond-req-listing-slashable-01".to_string(),
        status_feed_ref: "finding-status-feed-01".to_string(),
    }
}

/// Marketplace fixtures for the end-to-end bid-path test, mirroring the
/// construction in `tests/bidding.rs` with finding-flavored values. The
/// listed subject is the seller's finding server under the existing
/// `ToolServer` actor kind (ARCHITECTURE 7.3): no listing-schema change.
fn finding_namespace(keypair: &Keypair) -> GenericNamespaceOwnership {
    GenericNamespaceOwnership {
        namespace: "https://registry.seller.example".to_string(),
        owner_id: "seller-operator".to_string(),
        owner_name: Some("Seller Operator".to_string()),
        registry_url: "https://registry.seller.example".to_string(),
        signer_public_key: keypair.public_key(),
        registered_at: 1,
        transferred_from_owner_id: None,
    }
}

fn signed_finding_listing(keypair: &Keypair) -> SignedGenericListing {
    let body = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: FINDING_LISTING_ID.to_string(),
        namespace: "https://registry.seller.example".to_string(),
        published_at: 10,
        expires_at: Some(5_000),
        status: GenericListingStatus::Active,
        namespace_ownership: finding_namespace(keypair),
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: FINDING_SERVER_ID.to_string(),
            display_name: Some("Finding server".to_string()),
            metadata_url: Some("https://registry.seller.example/finding/f3a9".to_string()),
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
    SignedGenericListing::sign(body, keypair).test_expect("sign finding listing")
}

fn finding_listing_entry(operator: &Keypair, price_units: u64) -> Listing {
    Listing {
        rank: 1,
        listing: signed_finding_listing(operator),
        pricing: SignedListingPricingHint::sign(
            ListingPricingHint {
                schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
                listing_id: FINDING_LISTING_ID.to_string(),
                namespace: "https://registry.seller.example".to_string(),
                provider_operator_id: "seller-operator".to_string(),
                capability_scope: finding_scope(),
                price_per_call: MonetaryAmount {
                    units: price_units,
                    currency: "USD".to_string(),
                },
                sla: ListingSla {
                    max_latency_ms: 200,
                    availability_bps: 9_995,
                    throughput_rps: 100,
                },
                revocation_rate_bps: 5,
                recent_receipts_volume: 2_500,
                issued_at: 110,
                expires_at: 600,
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
            valid_until: 1_000,
            generated_at: 100,
        },
    }
}

fn finding_bid_request() -> BidRequest {
    BidRequest {
        schema: BID_REQUEST_SCHEMA.to_string(),
        agent_id: "buyer-agent-7".to_string(),
        listing_id: FINDING_LISTING_ID.to_string(),
        max_price_per_call: MonetaryAmount {
            units: 900,
            currency: "USD".to_string(),
        },
        window_seconds: 3_600,
        requested_scope: RequestedScope {
            server_id: FINDING_SERVER_ID.to_string(),
            tool_name: "read_finding".to_string(),
            max_invocations: Some(1),
            capability_scope_prefix: finding_scope(),
        },
        issued_at: 120,
    }
}

/// Passes today: buying a finding reuses the existing marketplace bid
/// shape unchanged. The listing id points at a finding listing instead of
/// a tool listing; the bid itself needs zero new fields.
#[test]
fn finding_purchase_reuses_marketplace_bid_shape() {
    assert!(finding_bid_request().validate().is_ok());
}

/// Passes today: a finding listing clears the REAL `bid()` path with the
/// colon-segment scope convention, and the minted token is the one-shot
/// priced grant the reveal needs. Also pins the M4 seam: `bid()` mints
/// grants with empty constraints (`bidding.rs:396`), so the delivery
/// binding (`OutputDigestSha256`) has nowhere to ride until
/// `BidMintContext` grows provider-supplied constraints.
#[test]
fn finding_purchase_clears_the_real_bid_path() {
    let operator = Keypair::generate();
    let agent = Keypair::generate();
    let listing = finding_listing_entry(&operator, 900);
    let request =
        SignedBidRequest::sign(finding_bid_request(), &agent).test_expect("sign finding bid");

    let ask = bid(
        &request,
        BidMintContext {
            listing: &listing,
            issuer_keypair: &operator,
            agent_subject: agent.public_key(),
            token_id: "finding-token-0001".to_string(),
            now: 120,
        },
    )
    .test_expect("finding bid clears the marketplace path");

    assert_eq!(ask.body.schema, ASK_RESPONSE_SCHEMA);
    assert_eq!(ask.body.quoted_price.units, 900);
    let grant = &ask.body.token_offer.scope.grants[0];
    assert_eq!(grant.tool_name, "read_finding");
    assert_eq!(grant.max_invocations, Some(1));
    assert_eq!(
        grant.max_total_cost,
        Some(MonetaryAmount {
            units: 900,
            currency: "USD".to_string(),
        })
    );
    // Seam pin (M4): no delivery constraint can be attached yet.
    assert!(grant.constraints.is_empty());
}

/// Passes today: the elicitation ceiling is deterministic, monotone in the
/// re-derivation quote, and hard-capped by the purchasing allocation. It
/// makes no claim about the finding's true value.
#[test]
fn finding_bid_ceiling_is_bounded_and_budget_capped() {
    let mut basis = FindingBidBasis {
        rederivation_quote_units: 4_200,
        would_have_run_bps: 6_000,
        sibling_redundancy_bps: 2_500,
        guarantee_class_bps: 10_000,
        budget_remaining_units: 10_000,
    };
    let ceiling = finding_bid_ceiling(&basis);
    // 4200 x 0.60 x 0.75 x 1.00 = 1890.
    assert_eq!(ceiling, 1_890);
    assert!(ceiling <= basis.rederivation_quote_units);

    basis.budget_remaining_units = 500;
    assert_eq!(finding_bid_ceiling(&basis), 500);

    basis.would_have_run_bps = 0;
    assert_eq!(finding_bid_ceiling(&basis), 0);
}

/// Specifies the desired end-to-end flow (memo section 6.2). Ignored
/// because the reveal seam does not exist yet; the panic below names the
/// first missing piece in dependency order.
#[test]
#[ignore = "specifies the unimplemented cognition-market reveal flow; see docs/research/agent-cognition-market.md section 6.2"]
fn cognition_market_reveal_flow_spec() {
    let finding = sealed_negative_result();

    // 1. Commit: the finding artifact carries the payload commitment and
    //    the metered evidence refs a buyer verifies before bidding.
    assert_eq!(finding.schema, FINDING_SCHEMA_V1);
    assert!(!finding.evidence_receipt_ids.is_empty());

    // 2. Bid/accept: covered by the passing tests above, including the
    //    real bid() path and the pinned empty-constraints seam.

    // 3. Escrow: MustPrepay hold (small amounts) or ChioEscrow terms
    //    (large amounts) with release/refund as the only terminal states.

    // 4. Reveal = delivery proof. MISSING SEAMS, in dependency order:
    //    a. a `read_finding` tool contract that refuses to sign a delivery
    //       receipt unless receipt.content_hash == finding.payload_sha256
    //       (carried as a provider-minted OutputDigestSha256 constraint;
    //       see the empty-constraints pin above);
    //    b. escrow release wired from that receipt's Merkle inclusion;
    //    c. a `FabricatedFindingEvidence` abuse class + replay challenge
    //       decision rule feeding the existing sanction/slash gate;
    //    d. a finding-status feed (revocation-oracle pattern) checked for
    //       non-inclusion at purchase time.
    let delivery = mediated_reveal_delivery_receipt(&finding);
    let receipt_id = match delivery {
        Some(receipt_id) => receipt_id,
        None => panic!(
            "missing seam (a): no governed read_finding tool contract binds \
             receipt content_hash to the committed payload_sha256"
        ),
    };

    // 5. Post-reveal: the delivery receipt anchors the dispute window and
    //    the challenge evidence chain.
    assert!(!receipt_id.is_empty());
}
