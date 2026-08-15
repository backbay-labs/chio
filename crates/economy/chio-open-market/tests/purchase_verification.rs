#![cfg(feature = "cognition-market-experimental")]

//! Direct coverage for `verify_purchase_context_pure`, the deterministic
//! decision that a buyer-presented purchase context is genuine.
//!
//! One valid carrier is assembled from real signed artifacts; every other
//! case changes exactly one thing and asserts the exact typed rejection, so
//! a dropped or reordered check cannot pass unnoticed.
//!
//! The four members the verifier resolves only by admission digest (market
//! terms, seller backing, verifier profile, verifier report) travel as
//! opaque canonical text. That is precisely their contract on this path:
//! the verifier re-derives their envelope identities and never parses them,
//! and their deep validity was proved at activation time.

use chio_finding::{
    compute_admission_id, compute_authorization_id, compute_finding_id, sign_finding, Finding,
    FindingAdmission, FindingAuthorityKeyPolicy, FindingDescriptor, FindingError,
    FindingEvidenceClass, FindingFeeEvent, FindingFeeTerminalBinding, FindingGuaranteeClass,
    FindingOutcomeClass, FindingPayee, FindingPoolBinding, FindingPurchaseContext,
    FindingSellerAuthorization, SignedFindingAdmission, SignedFindingSellerAuthorization,
    FINDING_ADMISSION_SCHEMA_V1, FINDING_SCHEMA_V1, FINDING_SELLER_AUTHORIZATION_SCHEMA_V1,
    PURCHASE_CONTEXT_MAX_ENCODED_BYTES, PURCHASE_CONTEXT_SCHEMA,
};
use chio_open_market::{
    bidding::{
        bid, AcceptedBid, BidMintContext, BidRequest, RequestedScope, ReservationReceipt,
        SignedAcceptedBid, SignedAskResponse, SignedBidRequest, SignedReservationReceipt,
        ACCEPTED_BID_SCHEMA, BID_REQUEST_SCHEMA, RESERVATION_RECEIPT_SCHEMA,
    },
    canonical_json_bytes,
    capability::{scope::MonetaryAmount, token::CapabilityToken},
    crypto::{sha256_hex, Keypair, PublicKey},
    listing::{
        GenericListingActorKind, GenericListingArtifact, GenericListingBoundary,
        GenericListingCompatibilityReference, GenericListingFreshnessState,
        GenericListingReplicaFreshness, GenericListingStatus, GenericListingSubject,
        GenericNamespaceOwnership, GenericRegistryPublisher, GenericRegistryPublisherRole, Listing,
        ListingPricingHint, ListingSla, SignedGenericListing, SignedListingPricingHint,
        GENERIC_LISTING_ARTIFACT_SCHEMA, LISTING_PRICING_HINT_SCHEMA,
    },
    purchase_verification::{
        derive_payment_operation_id, derive_purchase_intent_id, verify_purchase_context_pure,
        PurchaseVerificationAuthorities, PurchaseVerificationError, PurchaseVerificationInputs,
        PurchaseVerificationOutcome,
    },
};
use chio_test_support::prelude::*;

const VENUE_ID: &str = "venue-wedge";
const SERVER_ID: &str = "finding-server.seller.example";
const LISTING_ID: &str = "listing-finding-purchase-0001";
const TOOL_NAME: &str = "read_finding";
const AGENT_ID: &str = "buyer-agent-7";
const NAMESPACE: &str = "https://registry.seller.example";
const OPERATOR_ID: &str = "seller-operator";
const RESERVATION_ID: &str = "reservation-0001";
const RESERVATION_STORE_KEY: &str = "reservations/listing-finding-purchase-0001/reservation-0001";
const TOKEN_ID: &str = "finding-purchase-token-0001";
const MEDIA_TYPE: &str = "application/json";
const PAYOUT_DESTINATION: &str = "rail:venue-ledger:seller-42";
const ISSUED_AT: u64 = 1_700_000_000;
const NOW: u64 = 1_750_000_000;
const ADMISSION_EXPIRES_AT: u64 = 1_890_000_000;
const WINDOW_EXPIRES_AT: u64 = 1_900_000_000;
const PRICE_UNITS: u64 = 300;

// ---------------------------------------------------------------------------
// Encoding and digest helpers
// ---------------------------------------------------------------------------

/// Standard base64 (RFC 4648, padded): the exact transport encoding the
/// carrier decoder accepts.
fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).copied().map_or(0, u32::from);
        let third = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (first << 16) | (second << 8) | third;
        encoded.push(char::from(ALPHABET[((triple >> 18) & 0x3f) as usize]));
        encoded.push(char::from(ALPHABET[((triple >> 12) & 0x3f) as usize]));
        encoded.push(if chunk.len() > 1 {
            char::from(ALPHABET[((triple >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            char::from(ALPHABET[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    encoded
}

fn canonical_text<T: serde::Serialize>(value: &T) -> String {
    let bytes = canonical_json_bytes(value).test_expect("canonical bytes");
    String::from_utf8(bytes).test_expect("canonical utf8")
}

fn digest_of<T: serde::Serialize>(value: &T) -> String {
    sha256_hex(&canonical_json_bytes(value).test_expect("canonical bytes"))
}

/// Digest of an already-canonical carried member, which is what the
/// verifier re-derives from the carrier text.
fn digest_text(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

/// A carried member the verifier resolves only by digest.
fn opaque_member(tag: &str) -> String {
    canonical_text(&serde_json::json!({ "member": tag }))
}

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

// ---------------------------------------------------------------------------
// Artifact builders
// ---------------------------------------------------------------------------

fn signed_finding(issuer: &Keypair, media_type: &str) -> Finding {
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#cognition-market-purchase".to_string(),
            context_sha256: hex64('a'),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: hex64('b'),
        payload_media_type: media_type.to_string(),
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
        issued_at: ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding).test_expect("finding id");
    sign_finding(finding, issuer).test_expect("sign finding")
}

fn signed_listing(operator: &Keypair, published_at: u64) -> SignedGenericListing {
    let body = GenericListingArtifact {
        schema: GENERIC_LISTING_ARTIFACT_SCHEMA.to_string(),
        listing_id: LISTING_ID.to_string(),
        namespace: NAMESPACE.to_string(),
        published_at,
        expires_at: Some(WINDOW_EXPIRES_AT),
        status: GenericListingStatus::Active,
        namespace_ownership: GenericNamespaceOwnership {
            namespace: NAMESPACE.to_string(),
            owner_id: OPERATOR_ID.to_string(),
            owner_name: Some("Seller Operator".to_string()),
            registry_url: NAMESPACE.to_string(),
            signer_public_key: operator.public_key(),
            registered_at: 1,
            transferred_from_owner_id: None,
        },
        subject: GenericListingSubject {
            actor_kind: GenericListingActorKind::ToolServer,
            actor_id: SERVER_ID.to_string(),
            display_name: Some("Finding server".to_string()),
            metadata_url: Some(format!("{NAMESPACE}/finding")),
            resolution_url: None,
            homepage_url: None,
        },
        compatibility: GenericListingCompatibilityReference {
            source_schema: "chio.certify.check.v1".to_string(),
            source_artifact_id: format!("artifact-{LISTING_ID}"),
            source_artifact_sha256: format!("sha-{LISTING_ID}"),
        },
        boundary: GenericListingBoundary::default(),
    };
    SignedGenericListing::sign(body, operator).test_expect("sign listing")
}

struct PricingSpec<'a> {
    operator: &'a Keypair,
    listing_id: &'a str,
    capability_scope: &'a str,
    price_units: u64,
}

fn signed_pricing(spec: &PricingSpec<'_>) -> SignedListingPricingHint {
    SignedListingPricingHint::sign(
        ListingPricingHint {
            schema: LISTING_PRICING_HINT_SCHEMA.to_string(),
            listing_id: spec.listing_id.to_string(),
            namespace: NAMESPACE.to_string(),
            provider_operator_id: OPERATOR_ID.to_string(),
            capability_scope: spec.capability_scope.to_string(),
            price_per_call: usd(spec.price_units),
            sla: ListingSla {
                max_latency_ms: 200,
                availability_bps: 9_995,
                throughput_rps: 100,
            },
            revocation_rate_bps: 5,
            recent_receipts_volume: 2_500,
            issued_at: ISSUED_AT,
            expires_at: WINDOW_EXPIRES_AT,
        },
        spec.operator,
    )
    .test_expect("sign pricing hint")
}

fn listing_entry(listing: &SignedGenericListing, pricing: &SignedListingPricingHint) -> Listing {
    Listing {
        rank: 1,
        listing: listing.clone(),
        pricing: pricing.clone(),
        publisher: GenericRegistryPublisher {
            role: GenericRegistryPublisherRole::Origin,
            operator_id: OPERATOR_ID.to_string(),
            operator_name: Some("Seller Operator".to_string()),
            registry_url: NAMESPACE.to_string(),
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

struct AuthorizationSpec<'a> {
    issuer: &'a Keypair,
    seller: PublicKey,
    finding_id: &'a str,
    listing_id: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
}

fn signed_authorization(spec: &AuthorizationSpec<'_>) -> SignedFindingSellerAuthorization {
    let mut authorization = FindingSellerAuthorization {
        schema: FINDING_SELLER_AUTHORIZATION_SCHEMA_V1.to_string(),
        authorization_id: String::new(),
        finding_id: spec.finding_id.to_string(),
        finding_artifact_sha256: hex64('d'),
        listing_id: spec.listing_id.to_string(),
        issuer: spec.issuer.public_key(),
        seller: spec.seller.clone(),
        provider_server_id: spec.server_id.to_string(),
        provider_tool: spec.tool_name.to_string(),
        payee: FindingPayee::Beneficiary {
            destination: PAYOUT_DESTINATION.to_string(),
            currency: "USD".to_string(),
        },
        revocation_status_ref: "revocations/seller-auth".to_string(),
        issued_at: ISSUED_AT,
        expires_at: WINDOW_EXPIRES_AT,
    };
    authorization.authorization_id =
        compute_authorization_id(&authorization).test_expect("authorization id");
    SignedFindingSellerAuthorization::sign(authorization, spec.issuer)
        .test_expect("sign authorization")
}

fn key_policy(seed: u8, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: ISSUED_AT,
        valid_until: WINDOW_EXPIRES_AT,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn fee_terminal(event: FindingFeeEvent, units: u64, fill: char) -> FindingFeeTerminalBinding {
    FindingFeeTerminalBinding {
        fee_schedule_envelope_sha256: hex64('5'),
        event,
        payer: OPERATOR_ID.to_string(),
        amount: usd(units),
        pool_principal_id: "pool:audit".to_string(),
        rail_destination: "rail:venue-ledger:audit-pool".to_string(),
        instruction_sha256: hex64(fill),
        observation_sha256: hex64('c'),
    }
}

/// Every identity and envelope digest the venue signs into one admission.
struct AdmissionSpec<'a> {
    venue: PublicKey,
    venue_id: &'a str,
    finding_id: &'a str,
    listing_id: &'a str,
    listing_sha256: String,
    pricing_hint_sha256: String,
    market_terms_sha256: String,
    seller_backing_sha256: String,
    seller_authorization_sha256: String,
    verifier_profile_sha256: String,
    verifier_report_sha256: String,
}

fn signed_admission(signer: &Keypair, spec: &AdmissionSpec<'_>) -> SignedFindingAdmission {
    let mut admission = FindingAdmission {
        schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
        admission_id: String::new(),
        venue: spec.venue.clone(),
        venue_id: spec.venue_id.to_string(),
        finding_id: spec.finding_id.to_string(),
        finding_artifact_sha256: hex64('d'),
        seller_authorization_envelope_sha256: spec.seller_authorization_sha256.clone(),
        listing_id: spec.listing_id.to_string(),
        listing_envelope_sha256: spec.listing_sha256.clone(),
        server_id: SERVER_ID.to_string(),
        metadata_url: format!("{NAMESPACE}/finding/{}", spec.finding_id),
        pricing_hint_envelope_sha256: spec.pricing_hint_sha256.clone(),
        capability_scope: format!("finding:{}", spec.finding_id),
        publisher_operator_id: OPERATOR_ID.to_string(),
        payee_destination: PAYOUT_DESTINATION.to_string(),
        fee_schedule_envelope_sha256: hex64('5'),
        verifier_report_id: hex64('7'),
        verifier_report_envelope_sha256: spec.verifier_report_sha256.clone(),
        terms_envelope_sha256: spec.market_terms_sha256.clone(),
        profile_envelope_sha256: spec.verifier_profile_sha256.clone(),
        fee_terminals: vec![
            fee_terminal(FindingFeeEvent::Publication, 5, '9'),
            fee_terminal(
                FindingFeeEvent::ParticipationEpoch { epoch_index: 0 },
                3,
                'b',
            ),
        ],
        backing_allocation_id: hex64('e'),
        backing_envelope_sha256: spec.seller_backing_sha256.clone(),
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
        issued_at: ISSUED_AT,
        expires_at: ADMISSION_EXPIRES_AT,
    };
    admission.admission_id = compute_admission_id(&admission).test_expect("admission id");
    SignedFindingAdmission::sign(admission, signer).test_expect("sign admission")
}

// ---------------------------------------------------------------------------
// The buyer handshake
// ---------------------------------------------------------------------------

struct BidSpec<'a> {
    listing_id: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    capability_scope: &'a str,
    max_invocations: Option<u32>,
}

fn bid_request_body(spec: &BidSpec<'_>) -> BidRequest {
    BidRequest {
        schema: BID_REQUEST_SCHEMA.to_string(),
        agent_id: AGENT_ID.to_string(),
        payout_destination: None,
        listing_id: spec.listing_id.to_string(),
        max_price_per_call: usd(PRICE_UNITS),
        window_seconds: 3_600,
        requested_scope: RequestedScope {
            server_id: spec.server_id.to_string(),
            tool_name: spec.tool_name.to_string(),
            max_invocations: spec.max_invocations,
            capability_scope_prefix: spec.capability_scope.to_string(),
        },
        issued_at: NOW,
    }
}

fn accepted_bid_body(ask: &SignedAskResponse, ask_digest: &str) -> AcceptedBid {
    AcceptedBid {
        schema: ACCEPTED_BID_SCHEMA.to_string(),
        listing_id: ask.body.listing_id.clone(),
        agent_id: ask.body.agent_id.clone(),
        bid_digest: ask.body.bid_digest.clone(),
        ask_digest: ask_digest.to_string(),
        bid_receipt_id: RESERVATION_ID.to_string(),
        quoted_price: ask.body.quoted_price.clone(),
        accepted_at: NOW + 60,
        token_id: ask.body.token_offer.id.clone(),
        token_subject: ask.body.token_offer.subject.clone(),
        token_expires_at: ask.body.token_offer.expires_at,
    }
}

fn reservation_body(ask: &SignedAskResponse, ask_digest: &str) -> ReservationReceipt {
    ReservationReceipt {
        schema: RESERVATION_RECEIPT_SCHEMA.to_string(),
        receipt_id: RESERVATION_ID.to_string(),
        agent_id: ask.body.agent_id.clone(),
        listing_id: ask.body.listing_id.clone(),
        ask_digest: ask_digest.to_string(),
        reserved_amount: ask.body.quoted_price.clone(),
    }
}

struct Handshake {
    bid_request: SignedBidRequest,
    ask: SignedAskResponse,
    accepted: SignedAcceptedBid,
    reservation: SignedReservationReceipt,
    capability: CapabilityToken,
}

/// Mint the ask through the real marketplace path, then bind the accepted
/// bid and the reservation receipt to it exactly as `accept()` does.
fn handshake(
    entry: &Listing,
    operator: &Keypair,
    agent: &Keypair,
    reservation_signer: &Keypair,
    spec: &BidSpec<'_>,
) -> Handshake {
    let bid_request =
        SignedBidRequest::sign(bid_request_body(spec), agent).test_expect("sign bid request");
    let ask = bid(
        &bid_request,
        BidMintContext {
            listing: entry,
            issuer_keypair: operator,
            agent_subject: agent.public_key(),
            token_id: TOKEN_ID.to_string(),
            now: NOW,
            grant_constraints: Vec::new(),
            dpop_required: Some(true),
        },
    )
    .test_expect("mint ask");
    let ask_digest = digest_of(&ask.body);
    let accepted = SignedAcceptedBid::sign(accepted_bid_body(&ask, &ask_digest), agent)
        .test_expect("sign accepted bid");
    let reservation =
        SignedReservationReceipt::sign(reservation_body(&ask, &ask_digest), reservation_signer)
            .test_expect("sign reservation receipt");
    let capability = ask.body.token_offer.clone();
    Handshake {
        bid_request,
        ask,
        accepted,
        reservation,
        capability,
    }
}

// ---------------------------------------------------------------------------
// The whole presentation, plus the knobs a case moves
// ---------------------------------------------------------------------------

struct Web {
    issuer: Keypair,
    operator: Keypair,
    agent: Keypair,
    venue_signer: Keypair,
    reservation_signer: Keypair,

    venue_key: PublicKey,
    venue_id: String,
    reservation_key: PublicKey,

    marker_finding_id: String,
    marker_listing_id: String,
    expected_output_digest: String,
    server_id: String,
    tool_name: String,
    arguments: serde_json::Value,

    admission_venue: PublicKey,
    admission_venue_id: String,
    admission_finding_id: String,
    admission_listing_id: String,

    finding: Finding,
    listing: SignedGenericListing,
    pricing: SignedListingPricingHint,
    authorization: SignedFindingSellerAuthorization,
    market_terms_json: String,
    seller_backing_json: String,
    verifier_profile_json: String,
    verifier_report_json: String,
    admission: SignedFindingAdmission,
    bid_request: SignedBidRequest,
    ask: SignedAskResponse,
    accepted: SignedAcceptedBid,
    reservation: SignedReservationReceipt,
    capability: CapabilityToken,
}

fn base_web() -> Web {
    let issuer = keypair(11);
    let operator = keypair(21);
    let agent = keypair(31);
    let venue_signer = keypair(6);
    let reservation_signer = keypair(41);

    let finding = signed_finding(&issuer, MEDIA_TYPE);
    let scope = format!("finding:{}", finding.finding_id);
    let listing = signed_listing(&operator, ISSUED_AT);
    let pricing = signed_pricing(&PricingSpec {
        operator: &operator,
        listing_id: LISTING_ID,
        capability_scope: &scope,
        price_units: PRICE_UNITS,
    });
    let authorization = signed_authorization(&AuthorizationSpec {
        issuer: &issuer,
        seller: operator.public_key(),
        finding_id: &finding.finding_id,
        listing_id: LISTING_ID,
        server_id: SERVER_ID,
        tool_name: TOOL_NAME,
    });
    let market_terms_json = opaque_member("market-terms");
    let seller_backing_json = opaque_member("seller-backing");
    let verifier_profile_json = opaque_member("verifier-profile");
    let verifier_report_json = opaque_member("verifier-report");
    let admission = signed_admission(
        &venue_signer,
        &AdmissionSpec {
            venue: venue_signer.public_key(),
            venue_id: VENUE_ID,
            finding_id: &finding.finding_id,
            listing_id: LISTING_ID,
            listing_sha256: digest_of(&listing),
            pricing_hint_sha256: digest_of(&pricing),
            market_terms_sha256: digest_text(&market_terms_json),
            seller_backing_sha256: digest_text(&seller_backing_json),
            seller_authorization_sha256: digest_of(&authorization),
            verifier_profile_sha256: digest_text(&verifier_profile_json),
            verifier_report_sha256: digest_text(&verifier_report_json),
        },
    );

    let entry = listing_entry(&listing, &pricing);
    let handshake = handshake(
        &entry,
        &operator,
        &agent,
        &reservation_signer,
        &BidSpec {
            listing_id: LISTING_ID,
            server_id: SERVER_ID,
            tool_name: TOOL_NAME,
            capability_scope: &scope,
            max_invocations: Some(1),
        },
    );

    Web {
        venue_key: venue_signer.public_key(),
        venue_id: VENUE_ID.to_string(),
        reservation_key: reservation_signer.public_key(),
        marker_finding_id: finding.finding_id.clone(),
        marker_listing_id: LISTING_ID.to_string(),
        expected_output_digest: finding.payload_sha256.clone(),
        server_id: SERVER_ID.to_string(),
        tool_name: TOOL_NAME.to_string(),
        arguments: serde_json::json!({ "finding_id": finding.finding_id }),
        admission_venue: venue_signer.public_key(),
        admission_venue_id: VENUE_ID.to_string(),
        admission_finding_id: finding.finding_id.clone(),
        admission_listing_id: LISTING_ID.to_string(),
        issuer,
        operator,
        agent,
        venue_signer,
        reservation_signer,
        finding,
        listing,
        pricing,
        authorization,
        market_terms_json,
        seller_backing_json,
        verifier_profile_json,
        verifier_report_json,
        admission,
        bid_request: handshake.bid_request,
        ask: handshake.ask,
        accepted: handshake.accepted,
        reservation: handshake.reservation,
        capability: handshake.capability,
    }
}

impl Web {
    fn scope(&self) -> String {
        format!("finding:{}", self.finding.finding_id)
    }

    fn context(&self) -> FindingPurchaseContext {
        FindingPurchaseContext {
            schema: PURCHASE_CONTEXT_SCHEMA.to_string(),
            finding_json: canonical_text(&self.finding),
            listing_envelope_json: canonical_text(&self.listing),
            pricing_hint_envelope_json: canonical_text(&self.pricing),
            venue_admission_envelope_json: canonical_text(&self.admission),
            market_terms_envelope_json: self.market_terms_json.clone(),
            seller_authorization_envelope_json: canonical_text(&self.authorization),
            verifier_profile_envelope_json: self.verifier_profile_json.clone(),
            seller_backing_envelope_json: self.seller_backing_json.clone(),
            verifier_report_envelope_json: self.verifier_report_json.clone(),
            bid_request_envelope_json: canonical_text(&self.bid_request),
            ask_response_envelope_json: canonical_text(&self.ask),
            accepted_bid_envelope_json: canonical_text(&self.accepted),
            reservation_receipt_envelope_json: canonical_text(&self.reservation),
            reservation_store_key: RESERVATION_STORE_KEY.to_string(),
            token_offer_json: canonical_text(&self.ask.body.token_offer),
        }
    }

    /// Re-sign the admission so it binds exactly the envelopes this context
    /// now carries. Cases that must reach a check sitting behind the
    /// admission's digest bindings call this after swapping a member.
    fn rebind_admission(&self, context: &mut FindingPurchaseContext) {
        let admission = signed_admission(
            &self.venue_signer,
            &AdmissionSpec {
                venue: self.admission_venue.clone(),
                venue_id: &self.admission_venue_id,
                finding_id: &self.admission_finding_id,
                listing_id: &self.admission_listing_id,
                listing_sha256: digest_text(&context.listing_envelope_json),
                pricing_hint_sha256: digest_text(&context.pricing_hint_envelope_json),
                market_terms_sha256: digest_text(&context.market_terms_envelope_json),
                seller_backing_sha256: digest_text(&context.seller_backing_envelope_json),
                seller_authorization_sha256: digest_text(
                    &context.seller_authorization_envelope_json,
                ),
                verifier_profile_sha256: digest_text(&context.verifier_profile_envelope_json),
                verifier_report_sha256: digest_text(&context.verifier_report_envelope_json),
            },
        );
        context.venue_admission_envelope_json = canonical_text(&admission);
    }

    fn verify_carrier(
        &self,
        carrier: &str,
    ) -> Result<PurchaseVerificationOutcome, PurchaseVerificationError> {
        verify_purchase_context_pure(
            &PurchaseVerificationInputs {
                marker_finding_id: &self.marker_finding_id,
                marker_listing_id: &self.marker_listing_id,
                expected_output_digest: &self.expected_output_digest,
                context_b64: carrier,
                capability: &self.capability,
                server_id: &self.server_id,
                tool_name: &self.tool_name,
                arguments: &self.arguments,
            },
            &PurchaseVerificationAuthorities {
                venue_authority: self.venue_key.clone(),
                venue_id: self.venue_id.clone(),
                reservation_authority: self.reservation_key.clone(),
            },
        )
    }

    fn verify_context(
        &self,
        context: &FindingPurchaseContext,
    ) -> Result<PurchaseVerificationOutcome, PurchaseVerificationError> {
        let carrier = base64_standard(&canonical_json_bytes(context).test_expect("carrier bytes"));
        self.verify_carrier(&carrier)
    }

    fn verify(&self) -> Result<PurchaseVerificationOutcome, PurchaseVerificationError> {
        self.verify_context(&self.context())
    }

    fn reject(&self) -> PurchaseVerificationError {
        self.verify().test_unwrap_err()
    }

    fn reject_context(&self, context: &FindingPurchaseContext) -> PurchaseVerificationError {
        self.verify_context(context).test_unwrap_err()
    }
}

// ---------------------------------------------------------------------------
// Case tables
//
// Every table pairs a label with the single change it applies, so a case
// that stops reaching its intended check names itself in the failure.
// ---------------------------------------------------------------------------

type ContextCase = (&'static str, fn(&mut FindingPurchaseContext));
type SubstitutionCase = (&'static str, fn(&Web, &mut FindingPurchaseContext));
type AuthorizationCase = (&'static str, fn(&Web) -> SignedFindingSellerAuthorization);
type AcceptedBidCase = (&'static str, fn(&mut AcceptedBid));
type CapabilityCase = (&'static str, fn(&mut CapabilityToken));
type ReservationCase = (&'static str, fn(&mut ReservationReceipt));

// ---------------------------------------------------------------------------
// The accepting case
// ---------------------------------------------------------------------------

#[test]
fn a_genuine_purchase_context_verifies_and_reports_its_bindings() {
    let web = base_web();
    let outcome = web
        .verify()
        .test_expect("genuine purchase context verifies");

    assert_eq!(outcome.finding.finding_id, web.finding.finding_id);
    assert_eq!(outcome.admission.body.listing_id, LISTING_ID);
    assert_eq!(
        outcome.seller_authorization.body.seller,
        web.operator.public_key()
    );
    assert_eq!(outcome.reservation_id, RESERVATION_ID);
    assert_eq!(outcome.reservation_store_key, RESERVATION_STORE_KEY);
    assert_eq!(outcome.accepted_price, usd(PRICE_UNITS));
    assert_eq!(outcome.payer_key_hex, web.agent.public_key().to_hex());
    assert_eq!(web.ask.body.bid_digest, digest_of(&web.bid_request.body));
    assert_eq!(
        outcome.bid_request_envelope_sha256,
        digest_of(&web.bid_request)
    );
    assert_ne!(outcome.bid_request_envelope_sha256, web.ask.body.bid_digest);
    assert_eq!(
        outcome.accepted_bid_envelope_sha256,
        digest_of(&web.accepted)
    );
    assert_eq!(
        outcome.venue_admission_envelope_sha256,
        digest_of(&web.admission)
    );
    assert_eq!(
        outcome.purchase_intent_id,
        derive_purchase_intent_id(RESERVATION_ID)
    );
    assert_eq!(
        outcome.authoritative_payment_operation_id,
        derive_payment_operation_id(RESERVATION_ID)
    );
}

// ---------------------------------------------------------------------------
// Carrier decode and bound failures
// ---------------------------------------------------------------------------

#[test]
fn carrier_decode_and_bound_failures_reject() {
    let web = base_web();
    let context = web.context();
    let bytes = canonical_json_bytes(&context).test_expect("carrier bytes");
    let carrier = base64_standard(&bytes);

    assert_eq!(
        web.verify_carrier("").test_unwrap_err(),
        PurchaseVerificationError::Carrier(FindingError::SizeLimitExceeded(
            "purchase_context.encoded"
        )),
        "an empty presentation must not decode"
    );
    assert_eq!(
        web.verify_carrier(&"A".repeat(PURCHASE_CONTEXT_MAX_ENCODED_BYTES + 1))
            .test_unwrap_err(),
        PurchaseVerificationError::Carrier(FindingError::SizeLimitExceeded(
            "purchase_context.encoded"
        )),
        "the encoded bound is enforced before any decode work"
    );
    assert_eq!(
        web.verify_carrier("not base64 at all!!").test_unwrap_err(),
        PurchaseVerificationError::Carrier(FindingError::InvalidField("purchase_context.encoded"))
    );
    assert_eq!(
        web.verify_carrier(&base64_standard(b"{}"))
            .test_unwrap_err(),
        PurchaseVerificationError::Carrier(FindingError::InvalidField("purchase_context"))
    );

    let pretty = serde_json::to_vec_pretty(&context).test_expect("pretty carrier");
    assert_eq!(
        web.verify_carrier(&base64_standard(&pretty))
            .test_unwrap_err(),
        PurchaseVerificationError::Carrier(FindingError::NonCanonicalBytes("purchase_context"))
    );

    let mut foreign_schema = context.clone();
    foreign_schema.schema = "chio.finding.purchase-context.v9".to_string();
    assert!(matches!(
        web.reject_context(&foreign_schema),
        PurchaseVerificationError::Carrier(FindingError::UnsupportedSchema(_))
    ));

    let mut non_canonical_member = context;
    non_canonical_member.finding_json = "{ \"schema\" : \"chio.finding.v1\" }".to_string();
    assert_eq!(
        web.reject_context(&non_canonical_member),
        PurchaseVerificationError::Carrier(FindingError::NonCanonicalBytes("finding_json"))
    );

    // The accepting carrier is unchanged by any of the above.
    web.verify_carrier(&carrier)
        .test_expect("the untouched carrier still verifies");
}

#[test]
fn a_member_that_is_not_its_artifact_rejects() {
    // Each label is the field name the verifier reports for the member it
    // could not parse. Members behind the admission's digest bindings need
    // the admission re-bound first so the parse is what actually fails.
    let rebind: [ContextCase; 3] = [
        ("listing", |context| {
            context.listing_envelope_json = opaque_member("listing");
        }),
        ("pricing_hint", |context| {
            context.pricing_hint_envelope_json = opaque_member("pricing-hint");
        }),
        ("seller_authorization", |context| {
            context.seller_authorization_envelope_json = opaque_member("seller-authorization");
        }),
    ];
    for (member, mutate) in rebind {
        let web = base_web();
        let mut context = web.context();
        mutate(&mut context);
        web.rebind_admission(&mut context);
        assert_eq!(
            web.reject_context(&context),
            PurchaseVerificationError::Member(member),
            "member {member}"
        );
    }

    let direct: [ContextCase; 6] = [
        ("finding_json", |context| {
            context.finding_json = opaque_member("finding");
        }),
        ("venue_admission", |context| {
            context.venue_admission_envelope_json = opaque_member("venue-admission");
        }),
        ("ask_response", |context| {
            context.ask_response_envelope_json = opaque_member("ask-response");
        }),
        ("bid_request", |context| {
            context.bid_request_envelope_json = opaque_member("bid-request");
        }),
        ("accepted_bid", |context| {
            context.accepted_bid_envelope_json = opaque_member("accepted-bid");
        }),
        ("reservation_receipt", |context| {
            context.reservation_receipt_envelope_json = opaque_member("reservation-receipt");
        }),
    ];
    for (member, mutate) in direct {
        let web = base_web();
        let mut context = web.context();
        mutate(&mut context);
        assert_eq!(
            web.reject_context(&context),
            PurchaseVerificationError::Member(member),
            "member {member}"
        );
    }
}

// ---------------------------------------------------------------------------
// The signed finding anchor
// ---------------------------------------------------------------------------

#[test]
fn a_finding_that_fails_its_own_verification_rejects() {
    let mut web = base_web();
    web.finding.descriptor.topic = "repo:backbay/chio#substituted".to_string();
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::Finding(FindingError::FindingIdMismatch)
    );

    let mut web = base_web();
    web.finding.signature = hex64('0');
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::Finding(FindingError::SignatureInvalid)
    );
}

#[test]
fn a_finding_the_marker_did_not_name_rejects() {
    let mut web = base_web();
    web.marker_finding_id = hex64('9');
    assert_eq!(web.reject(), PurchaseVerificationError::MarkerMismatch);
}

#[test]
fn a_payload_commitment_that_is_not_the_grant_digest_rejects() {
    let mut web = base_web();
    web.expected_output_digest = hex64('9');
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::PayloadDigestMismatch
    );
}

#[test]
fn an_absent_reveal_media_type_never_reaches_the_media_guard() {
    // The media-type guard is defence in depth: the finding validator the
    // anchor step runs already refuses a blank advertised type, so the
    // rejection arrives from the finding rather than from the guard.
    let mut web = base_web();
    web.finding.payload_media_type = "   ".to_string();
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::Finding(FindingError::EmptyField("payload_media_type"))
    );
}

#[test]
fn request_arguments_naming_another_finding_reject() {
    let mut web = base_web();
    web.arguments = serde_json::json!({ "finding_id": hex64('9') });
    assert_eq!(web.reject(), PurchaseVerificationError::ArgumentMismatch);

    let mut web = base_web();
    web.arguments = serde_json::json!({ "listing_id": LISTING_ID });
    assert_eq!(web.reject(), PurchaseVerificationError::ArgumentMismatch);
}

// ---------------------------------------------------------------------------
// The venue admission
// ---------------------------------------------------------------------------

#[test]
fn an_admission_outside_the_pinned_venue_authority_rejects() {
    // The signer, the body venue, and the venue id are three independent
    // ways to present an admission this deployment never issued.
    let mut web = base_web();
    web.venue_signer = keypair(9);
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::Admission(FindingError::AuthorityMismatch("admission"))
    );

    let mut web = base_web();
    web.admission_venue = keypair(9).public_key();
    web.venue_signer = keypair(9);
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::Admission(FindingError::AuthorityMismatch("admission"))
    );

    let mut web = base_web();
    web.admission_venue_id = "venue-elsewhere".to_string();
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::Admission(FindingError::AuthorityMismatch("admission"))
    );
}

#[test]
fn an_admission_issued_for_another_sale_rejects() {
    let mut web = base_web();
    web.admission_finding_id = hex64('9');
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::MarkerMismatch
    );

    let mut web = base_web();
    web.admission_listing_id = "listing-elsewhere".to_string();
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::MarkerMismatch
    );
}

#[test]
fn every_envelope_the_admission_binds_is_bound_independently() {
    // A validly signed but unbound envelope is still the wrong envelope,
    // so each member is substituted on its own and must be named exactly.
    let substitutions: [SubstitutionCase; 7] = [
        ("listing", |web, context| {
            context.listing_envelope_json =
                canonical_text(&signed_listing(&web.operator, ISSUED_AT + 1));
        }),
        ("pricing_hint", |web, context| {
            context.pricing_hint_envelope_json = canonical_text(&signed_pricing(&PricingSpec {
                operator: &web.operator,
                listing_id: LISTING_ID,
                capability_scope: &web.scope(),
                price_units: PRICE_UNITS + 1,
            }));
        }),
        ("market_terms", |_web, context| {
            context.market_terms_envelope_json = opaque_member("market-terms-elsewhere");
        }),
        ("seller_backing", |_web, context| {
            context.seller_backing_envelope_json = opaque_member("seller-backing-elsewhere");
        }),
        ("seller_authorization", |web, context| {
            context.seller_authorization_envelope_json =
                canonical_text(&signed_authorization(&AuthorizationSpec {
                    issuer: &web.issuer,
                    seller: web.operator.public_key(),
                    finding_id: &web.finding.finding_id,
                    listing_id: LISTING_ID,
                    server_id: SERVER_ID,
                    tool_name: "read_finding_v2",
                }));
        }),
        ("verifier_profile", |_web, context| {
            context.verifier_profile_envelope_json = opaque_member("verifier-profile-elsewhere");
        }),
        ("verifier_report", |_web, context| {
            context.verifier_report_envelope_json = opaque_member("verifier-report-elsewhere");
        }),
    ];
    for (member, substitute) in substitutions {
        let web = base_web();
        let mut context = web.context();
        substitute(&web, &mut context);
        assert_eq!(
            web.reject_context(&context),
            PurchaseVerificationError::AdmissionBindingMismatch(member),
            "member {member}"
        );
    }
}

// ---------------------------------------------------------------------------
// Envelope signatures behind the admission bindings
// ---------------------------------------------------------------------------

#[test]
fn an_unverifiable_envelope_signature_rejects() {
    // The admission is re-bound to the tampered bytes so the signature
    // check, not the digest binding, is what refuses.
    let mut web = base_web();
    web.listing.body.published_at += 1;
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::EnvelopeSignature("listing")
    );

    let mut web = base_web();
    web.pricing.body.recent_receipts_volume += 1;
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::EnvelopeSignature("pricing_hint")
    );

    // The handshake envelopes carry no admission binding, so tampering
    // alone is enough to reach their signature checks.
    let mut web = base_web();
    web.ask.body.issued_at += 1;
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::EnvelopeSignature("ask_response")
    );

    let mut web = base_web();
    web.bid_request.body.window_seconds += 1;
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::EnvelopeSignature("bid_request")
    );

    let mut web = base_web();
    web.accepted.body.accepted_at += 1;
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::EnvelopeSignature("accepted_bid")
    );
}

#[test]
fn a_pricing_hint_scoped_elsewhere_rejects() {
    let mut web = base_web();
    web.pricing = signed_pricing(&PricingSpec {
        operator: &web.operator,
        listing_id: "listing-elsewhere",
        capability_scope: &web.scope(),
        price_units: PRICE_UNITS,
    });
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::HandshakeBinding("pricing_scope")
    );

    let mut web = base_web();
    web.pricing = signed_pricing(&PricingSpec {
        operator: &web.operator,
        listing_id: LISTING_ID,
        capability_scope: &format!("finding:{}", hex64('9')),
        price_units: PRICE_UNITS,
    });
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::HandshakeBinding("pricing_scope")
    );
}

// ---------------------------------------------------------------------------
// The seller authorization
// ---------------------------------------------------------------------------

#[test]
fn a_seller_authorization_that_fails_its_own_verification_rejects() {
    let mut web = base_web();
    web.authorization.body.revocation_status_ref = "revocations/elsewhere".to_string();
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::SellerAuthorization(FindingError::ArtifactIdMismatch(
            "authorization_id"
        ))
    );

    // An envelope signed by anyone other than its embedded issuer is not
    // an issuer authorization at all.
    let mut web = base_web();
    web.authorization =
        SignedFindingSellerAuthorization::sign(web.authorization.body.clone(), &keypair(9))
            .test_expect("sign authorization with an interloper");
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::SellerAuthorization(FindingError::AuthorityMismatch(
            "seller_authorization"
        ))
    );
}

#[test]
fn a_seller_authorization_that_does_not_cover_this_sale_rejects() {
    // Each covered surface is moved on its own so a dropped conjunct in
    // the scope check cannot hide behind another.
    let cases: [AuthorizationCase; 5] = [
        ("finding", |web| {
            signed_authorization(&AuthorizationSpec {
                issuer: &web.issuer,
                seller: web.operator.public_key(),
                finding_id: &hex64('9'),
                listing_id: LISTING_ID,
                server_id: SERVER_ID,
                tool_name: TOOL_NAME,
            })
        }),
        ("listing", |web| {
            signed_authorization(&AuthorizationSpec {
                issuer: &web.issuer,
                seller: web.operator.public_key(),
                finding_id: &web.finding.finding_id,
                listing_id: "listing-elsewhere",
                server_id: SERVER_ID,
                tool_name: TOOL_NAME,
            })
        }),
        ("issuer", |web| {
            signed_authorization(&AuthorizationSpec {
                issuer: &keypair(9),
                seller: web.operator.public_key(),
                finding_id: &web.finding.finding_id,
                listing_id: LISTING_ID,
                server_id: SERVER_ID,
                tool_name: TOOL_NAME,
            })
        }),
        ("server", |web| {
            signed_authorization(&AuthorizationSpec {
                issuer: &web.issuer,
                seller: web.operator.public_key(),
                finding_id: &web.finding.finding_id,
                listing_id: LISTING_ID,
                server_id: "finding-server.elsewhere.example",
                tool_name: TOOL_NAME,
            })
        }),
        ("tool", |web| {
            signed_authorization(&AuthorizationSpec {
                issuer: &web.issuer,
                seller: web.operator.public_key(),
                finding_id: &web.finding.finding_id,
                listing_id: LISTING_ID,
                server_id: SERVER_ID,
                tool_name: "read_finding_v2",
            })
        }),
    ];
    for (surface, build) in cases {
        let mut web = base_web();
        web.authorization = build(&web);
        let mut context = web.context();
        web.rebind_admission(&mut context);
        assert_eq!(
            web.reject_context(&context),
            PurchaseVerificationError::SellerAuthorizationScope,
            "surface {surface}"
        );
    }
}

#[test]
fn a_token_issuer_no_one_authorized_rejects() {
    // The ask is minted by the listing operator; an authorization naming a
    // different seller leaves that issuer unvouched for.
    let mut web = base_web();
    web.authorization = signed_authorization(&AuthorizationSpec {
        issuer: &web.issuer,
        seller: keypair(7).public_key(),
        finding_id: &web.finding.finding_id,
        listing_id: LISTING_ID,
        server_id: SERVER_ID,
        tool_name: TOOL_NAME,
    });
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::UnauthorizedIssuer
    );
}

#[test]
fn an_ask_advertising_an_issuer_it_did_not_sign_with_rejects() {
    let mut web = base_web();
    web.ask = SignedAskResponse::sign(web.ask.body.clone(), &keypair(9))
        .test_expect("re-sign ask with an interloper");
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::HandshakeBinding("ask_issuer")
    );
}

// ---------------------------------------------------------------------------
// Bid, ask, and accepted-bid cross-binding
// ---------------------------------------------------------------------------

/// Reissue the whole handshake (bid, ask, accepted bid, reservation, and
/// the presented capability) around a bid that differs from the accepting
/// one in exactly one requested field.
fn web_with_requested_scope(tool_name: &str, max_invocations: Option<u32>) -> Web {
    let mut web = base_web();
    let scope = web.scope();
    let entry = listing_entry(&web.listing, &web.pricing);
    let reissued = handshake(
        &entry,
        &web.operator,
        &web.agent,
        &web.reservation_signer,
        &BidSpec {
            listing_id: LISTING_ID,
            server_id: SERVER_ID,
            tool_name,
            capability_scope: &scope,
            max_invocations,
        },
    );
    web.bid_request = reissued.bid_request;
    web.ask = reissued.ask;
    web.accepted = reissued.accepted;
    web.reservation = reissued.reservation;
    web.capability = reissued.capability;
    web
}

#[test]
fn a_bid_that_does_not_cross_bind_the_ask_rejects() {
    // A validly signed bid whose canonical digest is not the one the ask
    // quoted.
    let mut web = base_web();
    let mut body = web.bid_request.body.clone();
    body.issued_at += 1;
    web.bid_request = SignedBidRequest::sign(body, &web.agent).test_expect("re-sign bid request");
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::HandshakeBinding("bid_request")
    );

    // A reveal purchase is a single invocation; the whole handshake is
    // reissued so only the requested cardinality differs.
    let web = web_with_requested_scope(TOOL_NAME, Some(2));
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::HandshakeBinding("bid_request")
    );

    // A bid for a different tool than the reveal request names.
    let web = web_with_requested_scope("read_finding_preview", Some(1));
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::HandshakeBinding("bid_request")
    );
}

#[test]
fn a_bid_for_another_server_or_listing_rejects() {
    // The reveal targets a server the bid never asked for. The seller
    // authorization is reissued for the same target so the scope check
    // ahead of the bid check still passes.
    let mut web = base_web();
    web.server_id = "finding-server.elsewhere.example".to_string();
    web.authorization = signed_authorization(&AuthorizationSpec {
        issuer: &web.issuer,
        seller: web.operator.public_key(),
        finding_id: &web.finding.finding_id,
        listing_id: LISTING_ID,
        server_id: &web.server_id,
        tool_name: TOOL_NAME,
    });
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::HandshakeBinding("bid_request")
    );

    // The marked listing moves and every artifact the verifier compares
    // against the marker moves with it, leaving the bid alone behind.
    let mut web = base_web();
    web.marker_listing_id = "listing-elsewhere".to_string();
    web.admission_listing_id = "listing-elsewhere".to_string();
    web.authorization = signed_authorization(&AuthorizationSpec {
        issuer: &web.issuer,
        seller: web.operator.public_key(),
        finding_id: &web.finding.finding_id,
        listing_id: "listing-elsewhere",
        server_id: SERVER_ID,
        tool_name: TOOL_NAME,
    });
    web.pricing = signed_pricing(&PricingSpec {
        operator: &web.operator,
        listing_id: "listing-elsewhere",
        capability_scope: &web.scope(),
        price_units: PRICE_UNITS,
    });
    let mut context = web.context();
    web.rebind_admission(&mut context);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::HandshakeBinding("bid_request")
    );
}

#[test]
fn an_accepted_bid_that_does_not_cross_bind_the_ask_rejects() {
    let mutations: [AcceptedBidCase; 8] = [
        ("ask_digest", |body| body.ask_digest = hex64('9')),
        ("bid_digest", |body| body.bid_digest = hex64('9')),
        ("listing", |body| {
            body.listing_id = "listing-elsewhere".to_string();
        }),
        ("agent", |body| {
            body.agent_id = "buyer-agent-9".to_string();
        }),
        ("price", |body| body.quoted_price = usd(PRICE_UNITS + 1)),
        ("token_id", |body| {
            body.token_id = "finding-purchase-token-0002".to_string();
        }),
        ("token_subject", |body| {
            body.token_subject = keypair(9).public_key();
        }),
        ("token_expiry", |body| body.token_expires_at += 1),
    ];
    for (field, mutate) in mutations {
        let mut web = base_web();
        let mut body = web.accepted.body.clone();
        mutate(&mut body);
        web.accepted =
            SignedAcceptedBid::sign(body, &web.agent).test_expect("re-sign accepted bid");
        assert_eq!(
            web.reject(),
            PurchaseVerificationError::HandshakeBinding("accepted_bid"),
            "field {field}"
        );
    }

    // The acceptance must come from the token subject, not from anyone
    // else holding the same bytes.
    let mut web = base_web();
    web.accepted = SignedAcceptedBid::sign(web.accepted.body.clone(), &keypair(9))
        .test_expect("re-sign accepted bid with an interloper");
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::HandshakeBinding("accepted_bid")
    );
}

// ---------------------------------------------------------------------------
// The presented capability
// ---------------------------------------------------------------------------

#[test]
fn a_presented_capability_that_is_not_the_exact_offer_rejects() {
    // Byte identity, not field agreement: sharing an id, subject, or
    // expiry with the offer is never enough.
    let mutations: [CapabilityCase; 8] = [
        ("id", |token| {
            token.id = "finding-purchase-token-0002".to_string();
        }),
        ("issuer", |token| token.issuer = keypair(9).public_key()),
        ("subject", |token| token.subject = keypair(9).public_key()),
        ("issued_at", |token| token.issued_at -= 1),
        ("expires_at", |token| token.expires_at += 1),
        ("grant_tool", |token| {
            token.scope.grants[0].tool_name = "read_finding_preview".to_string();
        }),
        ("grant_invocations", |token| {
            token.scope.grants[0].max_invocations = Some(2);
        }),
        ("grant_dpop", |token| {
            token.scope.grants[0].dpop_required = Some(false);
        }),
    ];
    for (field, mutate) in mutations {
        let mut web = base_web();
        mutate(&mut web.capability);
        assert_eq!(
            web.reject(),
            PurchaseVerificationError::TokenByteMismatch,
            "field {field}"
        );
    }

    // The carried token text must be the same bytes as well; a carrier
    // that ships a different token than the ask embedded is refused even
    // when the presented capability is genuine.
    let web = base_web();
    let mut context = web.context();
    let mut carried = web.capability.clone();
    carried.id = "finding-purchase-token-0002".to_string();
    context.token_offer_json = canonical_text(&carried);
    assert_eq!(
        web.reject_context(&context),
        PurchaseVerificationError::TokenByteMismatch
    );
}

// ---------------------------------------------------------------------------
// The reservation receipt
// ---------------------------------------------------------------------------

#[test]
fn a_reservation_receipt_outside_the_pinned_authority_rejects() {
    let mut web = base_web();
    web.reservation = SignedReservationReceipt::sign(web.reservation.body.clone(), &keypair(9))
        .test_expect("re-sign reservation with an interloper");
    assert_eq!(web.reject(), PurchaseVerificationError::ReservationReceipt);

    let mut web = base_web();
    web.reservation.body.reserved_amount = usd(PRICE_UNITS + 1);
    assert_eq!(
        web.reject(),
        PurchaseVerificationError::ReservationReceipt,
        "a tampered receipt body must fail the pinned-authority check"
    );
}

#[test]
fn a_reservation_that_does_not_bind_this_purchase_rejects() {
    let mutations: [ReservationCase; 5] = [
        ("agent", |body| {
            body.agent_id = "buyer-agent-9".to_string();
        }),
        ("listing", |body| {
            body.listing_id = "listing-elsewhere".to_string();
        }),
        ("ask_digest", |body| body.ask_digest = hex64('9')),
        ("receipt_id", |body| {
            body.receipt_id = "reservation-0002".to_string();
        }),
        ("amount", |body| {
            body.reserved_amount = usd(PRICE_UNITS + 1);
        }),
    ];
    for (member, mutate) in mutations {
        let mut web = base_web();
        let mut body = web.reservation.body.clone();
        mutate(&mut body);
        web.reservation = SignedReservationReceipt::sign(body, &web.reservation_signer)
            .test_expect("re-sign reservation receipt");
        assert_eq!(
            web.reject(),
            PurchaseVerificationError::ReservationBinding(member),
            "member {member}"
        );
    }
}
