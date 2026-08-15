//! Single-operator purchase coordinator for finding sales.
//!
//! The pure marketplace accept does not reserve funds: it verifies a
//! supplied reservation receipt and copies its id. This coordinator is
//! the authoritative other half. After a bid it authenticates the buyer
//! key, re-verifies the venue admission under the pinned venue authority
//! and the exact signed ask against it, preallocates the stable purchase
//! and payment identities, atomically opens the budget reservation and the
//! seller exposure encumbrance in the durable purchase store, and only
//! then signs the minimal compatibility reservation receipt under the
//! configured purchase authority. Reveals re-resolve the durable record
//! through the accepted bid's receipt id; no caller-shaped value overrides
//! it. Every artifact this coordinator signs passes its own validator
//! first, because both closes are one-shot and the store keeps the bytes.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use std::sync::Arc;

use chio_core::canonical_json_bytes;
use chio_core::capability::scope::{Constraint, FindingSettlementSelector, Operation};
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::Decision;
use chio_core::receipt::metadata::{
    DeliveryResult, FindingDelivery, FindingDeliverySettlementMode, FindingMediaTypeCheck,
    FINDING_DELIVERY_METADATA_KEY,
};
use chio_finding::{
    compute_failed_delivery_id, derive_purchase_key, verify_finding, verify_signed_bond_backing,
    verify_signed_seller_authorization, Finding, FindingFailedDelivery, FindingHoldReleaseTerminal,
    FindingPurchaseRecord, SignedFindingAdmission, SignedFindingBondBacking,
    SignedFindingFailedDelivery, SignedFindingPurchaseRecord, SignedFindingSellerAuthorization,
    FINDING_FAILED_DELIVERY_SCHEMA_V1, FINDING_PURCHASE_RECORD_SCHEMA_V1,
};
use chio_kernel::admission_operation::{
    AdmissionOperationState, AdmissionOperationStore, AdmissionReceiptMetadataV1,
    AdmissionTerminalReplay, ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::checkpoint::{
    checkpoint_body_sha256, checkpoint_log_id, validate_checkpoint, verify_checkpoint_signature,
    KernelCheckpoint, ReceiptInclusionProof,
};
use chio_kernel::tool_outcome::{ResolvedToolOutcomeV1, SettlementDispositionV1, ToolOutcomeStore};
use chio_open_market::bidding::{
    ReservationReceipt, SignedAskResponse, SignedBidRequest, SignedReservationReceipt,
    ASK_RESPONSE_SCHEMA, RESERVATION_RECEIPT_SCHEMA,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};
use chio_store_sqlite::{
    FindingPurchaseDeliveryInput, FindingPurchaseDenyInput, FindingPurchaseReservationInput,
    FindingPurchaseReservationRecord, FindingPurchaseReservationState,
    SqliteAdmissionOperationStore, SqliteFindingMarketStore, SqliteFindingPurchaseStore,
    SqliteToolOutcomeStore,
};

use super::finding_purchase_verifier::{PurchaseReservationReader, ReservationExpectation};

/// Domain separator for the deterministic reservation identity.
const RESERVATION_DOMAIN: &str = "chio.finding.reservation.v1";

/// Domain separator for the deterministic encumbrance identity.
const ENCUMBRANCE_DOMAIN: &str = "chio.finding.encumbrance.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedPurchaseTerminal {
    Delivered,
    Denied,
}

struct VerifiedPurchaseTerminal {
    delivery: FindingDelivery,
    settlement: SettlementDispositionV1,
}

/// Derive the reservation identity for one ask and payer. Reserving the
/// same accepted ask for the same payer is idempotent by construction.
#[must_use]
pub fn derive_reservation_id(ask_digest: &str, payer_hex: &str) -> String {
    sha256_hex(format!("{RESERVATION_DOMAIN}\0{ask_digest}\0{payer_hex}").as_bytes())
}

/// Typed rejections from the coordinator. Every variant refuses the
/// requested transition.
#[derive(Debug, thiserror::Error)]
pub enum PurchaseCoordinatorError {
    #[error("purchase authority key does not match the configured pin")]
    AuthorityPinMismatch,
    #[error("venue authority pin must be named and distinct from the signing authorities")]
    VenuePin,
    #[error("reserve request signature does not verify under the buyer key")]
    BuyerSignature,
    #[error("ask envelope rejected")]
    AskEnvelope,
    #[error("originating bid envelope rejected")]
    BidEnvelope,
    #[error("originating bid does not bind this ask")]
    BidBinding,
    #[error("embedded token offer rejected")]
    TokenOffer,
    #[error("ask is not live at the supplied clock")]
    AskWindow,
    #[error("venue admission does not verify under the pinned venue authority: {0}")]
    AdmissionEnvelope(String),
    #[error("venue admission is not live at the supplied clock")]
    AdmissionWindow,
    #[error("venue admission does not cover this sale")]
    AdmissionMismatch,
    #[error("venue admission is not the current admission for this finding")]
    AdmissionNotCurrent,
    #[error("admission-declared {0} authority is not the coordinator signing key")]
    DeclaredAuthorityMismatch(&'static str),
    #[error("admission-declared {0} authority window does not cover the reservation instant")]
    DeclaredAuthorityWindow(&'static str),
    #[error("seller authorization envelope rejected: {0}")]
    SellerAuthorization(String),
    #[error("seller authorization is not the admission-bound envelope for this sale")]
    SellerAuthorizationBinding,
    #[error("seller authorization is not live at the supplied clock")]
    SellerAuthorizationWindow,
    #[error("ask signer is neither the finding issuer nor the authorized seller")]
    AskMinterUnauthorized,
    #[error("the admission-bound finding artifact is unavailable or invalid: {0}")]
    FindingArtifact(String),
    #[error("ask grant is not the one-shot purchase delivery grant: {0}")]
    AskGrantShape(&'static str),
    #[error("purchase amounts must be exactly equal in units and currency")]
    AmountMismatch,
    #[error("realized spend exceeds the accepted price")]
    RealizedSpendAboveAcceptedPrice,
    #[error("durable kernel terminal evidence rejected: {0}")]
    TerminalEvidence(String),
    #[error("deny checkpoint evidence rejected: {0}")]
    CheckpointEvidence(String),
    #[error("admission-bound seller backing rejected: {0}")]
    SellerBacking(String),
    #[error("artifact body failed its own validator: {0}")]
    ArtifactValidation(String),
    #[error("payout destination was not admitted: {0}")]
    PayoutDestination(String),
    #[error("durable purchase store rejected the transition: {0}")]
    Store(String),
    #[error("reservation is not resolvable through the accepted bid")]
    UnknownReservation,
    #[error("artifact signing failed")]
    Signing,
    #[error("canonicalization failed")]
    Canonical,
}

/// The authoritative single-operator purchase coordinator.
pub struct FindingPurchaseCoordinator {
    store: SqliteFindingPurchaseStore,
    admissions: SqliteFindingMarketStore,
    operations: SqliteAdmissionOperationStore,
    outcomes: SqliteToolOutcomeStore,
    purchase_authority: Keypair,
    failed_delivery_authority: Keypair,
    venue_authority: PublicKey,
    venue_id: String,
}

impl FindingPurchaseCoordinator {
    /// Build the coordinator over the durable purchase store and the
    /// market store whose admission lifecycle gates every sale, verifying
    /// each signing key equals its configured public pin and that the
    /// venue the admissions must carry is named.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: SqliteFindingPurchaseStore,
        admissions: SqliteFindingMarketStore,
        operations: SqliteAdmissionOperationStore,
        outcomes: SqliteToolOutcomeStore,
        purchase_authority: Keypair,
        purchase_pin: &PublicKey,
        failed_delivery_authority: Keypair,
        failed_delivery_pin: &PublicKey,
        venue_pin: &PublicKey,
        venue_id: &str,
    ) -> Result<Self, PurchaseCoordinatorError> {
        if purchase_authority.public_key() != *purchase_pin
            || failed_delivery_authority.public_key() != *failed_delivery_pin
        {
            return Err(PurchaseCoordinatorError::AuthorityPinMismatch);
        }
        if venue_id.is_empty()
            || *venue_pin == purchase_authority.public_key()
            || *venue_pin == failed_delivery_authority.public_key()
        {
            return Err(PurchaseCoordinatorError::VenuePin);
        }
        Ok(Self {
            store,
            admissions,
            operations,
            outcomes,
            purchase_authority,
            failed_delivery_authority,
            venue_authority: venue_pin.clone(),
            venue_id: venue_id.to_owned(),
        })
    }

    /// Reserve funds and seller exposure for one accepted ask, then sign
    /// the compatibility reservation receipt.
    ///
    /// The buyer proves control of the token subject key by signing the
    /// exact ask digest; the venue admission is re-verified under the
    /// pinned venue authority and against its own liveness bounds before
    /// any identity it names reaches durable state; the seller
    /// authorization the admission binds by digest must be presented and
    /// must name the ask's minter; the allocation cap check and both
    /// reservations commit in one durable transaction. Replaying the same
    /// ask and payer returns the same signed receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &self,
        bid: &SignedBidRequest,
        ask: &SignedAskResponse,
        buyer_signature_over_ask_digest: &str,
        admission: &SignedFindingAdmission,
        seller_authorization: &SignedFindingSellerAuthorization,
        maximum_sale_exposure_units: u64,
        reservation_ttl_secs: u64,
        now: u64,
    ) -> Result<SignedReservationReceipt, PurchaseCoordinatorError> {
        if ask.body.schema != ASK_RESPONSE_SCHEMA
            || !matches!(ask.verify_signature(), Ok(true))
            || ask.body.token_offer.issuer != ask.signer_key
        {
            return Err(PurchaseCoordinatorError::AskEnvelope);
        }
        if !matches!(ask.body.token_offer.verify_signature(), Ok(true)) {
            return Err(PurchaseCoordinatorError::TokenOffer);
        }
        if ask.body.token_offer.issued_at > ask.body.issued_at
            || ask.body.token_offer.expires_at < ask.body.expires_at
        {
            return Err(PurchaseCoordinatorError::TokenOffer);
        }
        // An abandoned or expired ask must never open a reservation: the
        // reservation would hold seller collateral for a full TTL against a
        // quote the seller no longer stands behind.
        if now < ask.body.issued_at || now >= ask.body.expires_at {
            return Err(PurchaseCoordinatorError::AskWindow);
        }
        let ask_digest = canonical_json_bytes(&ask.body)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        bid.body
            .validate()
            .map_err(|_| PurchaseCoordinatorError::BidEnvelope)?;
        if !matches!(bid.verify_signature(), Ok(true)) {
            return Err(PurchaseCoordinatorError::BidEnvelope);
        }
        let bid_body_digest = canonical_json_bytes(&bid.body)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        if bid_body_digest != ask.body.bid_digest
            || bid.body.agent_id != ask.body.agent_id
            || bid.body.listing_id != ask.body.listing_id
            || bid.body.requested_scope.max_invocations != Some(1)
        {
            return Err(PurchaseCoordinatorError::BidBinding);
        }
        let payer = &ask.body.token_offer.subject;
        if bid.signer_key != *payer {
            return Err(PurchaseCoordinatorError::BidBinding);
        }
        let buyer_signature =
            chio_core::crypto::Signature::from_hex(buyer_signature_over_ask_digest)
                .map_err(|_| PurchaseCoordinatorError::BuyerSignature)?;
        if !payer.verify(ask_digest.as_bytes(), &buyer_signature) {
            return Err(PurchaseCoordinatorError::BuyerSignature);
        }
        // The finding, listing, and backing allocation this reservation
        // binds come from the admission body, so the admission is only
        // usable once it verifies under the pinned venue authority. An
        // unverified admission would let its presenter choose which
        // collateral the sale encumbers.
        chio_finding::verify_signed_admission(admission, &self.venue_authority, &self.venue_id)
            .map_err(|error| PurchaseCoordinatorError::AdmissionEnvelope(error.to_string()))?;
        if now < admission.body.issued_at || now >= admission.body.expires_at {
            return Err(PurchaseCoordinatorError::AdmissionWindow);
        }
        if admission.body.listing_id != ask.body.listing_id {
            return Err(PurchaseCoordinatorError::AdmissionMismatch);
        }
        // The admission pins the settlement authorities before any sale,
        // and standing verification accepts a settlement artifact only when
        // the declared key signed it at an instant inside the declared
        // window. The reservation instant is the instant both terminals
        // record, so both bindings hold here, where the clock enters: a
        // sale settled under an undeclared key or outside the window would
        // leave the paying buyer without standing to challenge.
        for (role, policy, signing_key) in [
            (
                "purchase",
                &admission.body.purchase_authority,
                self.purchase_authority.public_key(),
            ),
            (
                "failed-delivery",
                &admission.body.failed_delivery_authority,
                self.failed_delivery_authority.public_key(),
            ),
        ] {
            if policy.key != signing_key {
                return Err(PurchaseCoordinatorError::DeclaredAuthorityMismatch(role));
            }
            if now < policy.valid_from || now > policy.valid_until {
                return Err(PurchaseCoordinatorError::DeclaredAuthorityWindow(role));
            }
        }
        // The digest is derived from the envelope just verified, never
        // accepted from the caller: it gates the sale below and is signed
        // into the settlement record as the venue admission this sale was
        // made under.
        let admission_envelope_sha256 = canonical_json_bytes(admission)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        // An unexpired admission is not sufficient: activation of a newer
        // admission supersedes it in the durable market store, retiring
        // its terms, fees, collateral binding, and authority pins. Only
        // the byte-exact current admission for this finding transacts.
        let current = self
            .admissions
            .get_current_admission(&admission.body.finding_id)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
            .ok_or(PurchaseCoordinatorError::AdmissionNotCurrent)?;
        if current.envelope_sha256 != admission_envelope_sha256 {
            return Err(PurchaseCoordinatorError::AdmissionNotCurrent);
        }
        // The ask mints the delivery grant and prices the sale against the
        // seller's collateral, so its signer must be a principal the
        // finding issuer authorized for exactly this sale surface. The
        // admission commits to that authorization by envelope digest;
        // requiring the envelope here connects the minter to the issuer at
        // the moment exposure opens. Without it, any holder of the live
        // admission could mint an ask under its own key at its own price
        // and encumber the seller's allocation.
        let authorization_sha256 = canonical_json_bytes(seller_authorization)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        if authorization_sha256 != admission.body.seller_authorization_envelope_sha256 {
            return Err(PurchaseCoordinatorError::SellerAuthorizationBinding);
        }
        verify_signed_seller_authorization(seller_authorization)
            .map_err(|error| PurchaseCoordinatorError::SellerAuthorization(error.to_string()))?;
        let authorization = &seller_authorization.body;
        if authorization.finding_id != admission.body.finding_id
            || authorization.listing_id != admission.body.listing_id
        {
            return Err(PurchaseCoordinatorError::SellerAuthorizationBinding);
        }
        let finding_json = self
            .admissions
            .get_finding_bytes(&admission.body.finding_id)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
            .ok_or_else(|| {
                PurchaseCoordinatorError::FindingArtifact("finding is not retained".to_owned())
            })?;
        if sha256_hex(finding_json.as_bytes()) != admission.body.finding_artifact_sha256 {
            return Err(PurchaseCoordinatorError::FindingArtifact(
                "stored artifact digest does not match the admission".to_owned(),
            ));
        }
        let finding: Finding = serde_json::from_str(&finding_json).map_err(|error| {
            PurchaseCoordinatorError::FindingArtifact(format!("artifact JSON: {error}"))
        })?;
        verify_finding(&finding)
            .map_err(|error| PurchaseCoordinatorError::FindingArtifact(error.to_string()))?;
        if finding.finding_id != admission.body.finding_id
            || authorization.issuer != finding.issuer
            || authorization.finding_artifact_sha256 != admission.body.finding_artifact_sha256
        {
            return Err(PurchaseCoordinatorError::SellerAuthorizationBinding);
        }
        if now < authorization.issued_at || now >= authorization.expires_at {
            return Err(PurchaseCoordinatorError::SellerAuthorizationWindow);
        }
        if ask.signer_key != authorization.issuer && ask.signer_key != authorization.seller {
            return Err(PurchaseCoordinatorError::AskMinterUnauthorized);
        }
        let [grant] = ask.body.token_offer.scope.grants.as_slice() else {
            return Err(PurchaseCoordinatorError::AskEnvelope);
        };
        // Exposure opens only for the exact one-shot delivery grant the
        // reveal gate will admit: single invocation, DPoP-bound, committed
        // to an output digest, purchase-marked for this sale on the
        // admitted rail, and aimed at the authorized provider surface. A
        // looser grant would hold seller collateral for a reveal that can
        // never settle, or for more reveals than the sale sold.
        if grant.server_id != authorization.provider_server_id
            || grant.tool_name != authorization.provider_tool
            || grant.server_id != admission.body.server_id
            || bid.body.requested_scope.server_id != grant.server_id
            || bid.body.requested_scope.tool_name != grant.tool_name
            || bid.body.requested_scope.capability_scope_prefix != admission.body.capability_scope
        {
            return Err(PurchaseCoordinatorError::AskGrantShape("provider"));
        }
        if !ask.body.token_offer.scope.resource_grants.is_empty()
            || !ask.body.token_offer.scope.prompt_grants.is_empty()
        {
            return Err(PurchaseCoordinatorError::AskGrantShape("grant_families"));
        }
        if grant.max_invocations != Some(1) {
            return Err(PurchaseCoordinatorError::AskGrantShape("max_invocations"));
        }
        if grant.operations.as_slice() != [Operation::Invoke] {
            return Err(PurchaseCoordinatorError::AskGrantShape("operations"));
        }
        if grant.dpop_required != Some(true) {
            return Err(PurchaseCoordinatorError::AskGrantShape("dpop_required"));
        }
        let mut digests = grant
            .constraints
            .iter()
            .filter_map(|constraint| match constraint {
                Constraint::OutputDigestSha256(digest) => Some(digest),
                _ => None,
            });
        match (digests.next(), digests.next()) {
            (Some(digest), None) if digest == &finding.payload_sha256 => {}
            _ => return Err(PurchaseCoordinatorError::AskGrantShape("output_digest")),
        }
        let mut markers = grant
            .constraints
            .iter()
            .filter_map(|constraint| match constraint {
                Constraint::RequireFindingPurchase(marker) => Some(marker),
                _ => None,
            });
        match (markers.next(), markers.next()) {
            (Some(marker), None)
                if marker.finding_id == admission.body.finding_id
                    && marker.listing_id == ask.body.listing_id
                    && marker.settlement == FindingSettlementSelector::LocalReversibleHold => {}
            _ => return Err(PurchaseCoordinatorError::AskGrantShape("purchase_marker")),
        }
        let exact = |amount: &Option<chio_core::capability::scope::MonetaryAmount>| {
            amount.as_ref().is_some_and(|amount| {
                amount.units == ask.body.quoted_price.units
                    && amount.currency == ask.body.quoted_price.currency
            })
        };
        if !exact(&grant.max_cost_per_invocation) || !exact(&grant.max_total_cost) {
            return Err(PurchaseCoordinatorError::AmountMismatch);
        }
        let payer_hex = payer.to_hex();
        let reservation_id = derive_reservation_id(&ask_digest, &payer_hex);
        let encumbrance_id =
            sha256_hex(format!("{ENCUMBRANCE_DOMAIN}\0{reservation_id}").as_bytes());
        let bid_envelope_sha256 = canonical_json_bytes(bid)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        let input = FindingPurchaseReservationInput {
            reservation_id: &reservation_id,
            purchase_intent_id: &derive_purchase_intent_id(&reservation_id),
            authoritative_payment_operation_id: &derive_payment_operation_id(&reservation_id),
            payer_hex: &payer_hex,
            agent_id: &ask.body.agent_id,
            finding_id: &admission.body.finding_id,
            listing_id: &ask.body.listing_id,
            bid_envelope_sha256: &bid_envelope_sha256,
            ask_digest: &ask_digest,
            admission_envelope_sha256: &admission_envelope_sha256,
            amount_units: ask.body.quoted_price.units,
            currency: &ask.body.quoted_price.currency,
            expires_at: now.saturating_add(reservation_ttl_secs),
            encumbrance_id: &encumbrance_id,
            allocation_id: &admission.body.backing_allocation_id,
            maximum_sale_exposure_units,
            created_at: now,
        };
        self.store
            .open_reservation(&input)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
        let receipt = ReservationReceipt {
            schema: RESERVATION_RECEIPT_SCHEMA.to_owned(),
            receipt_id: reservation_id,
            agent_id: ask.body.agent_id.clone(),
            listing_id: ask.body.listing_id.clone(),
            ask_digest,
            reserved_amount: ask.body.quoted_price.clone(),
        };
        SignedReservationReceipt::sign(receipt, &self.purchase_authority)
            .map_err(|_| PurchaseCoordinatorError::Signing)
    }

    /// Resolve the authoritative reservation through the accepted bid's
    /// receipt id.
    pub fn resolve(
        &self,
        bid_receipt_id: &str,
    ) -> Result<FindingPurchaseReservationRecord, PurchaseCoordinatorError> {
        self.store
            .get_reservation(bid_receipt_id)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
            .ok_or(PurchaseCoordinatorError::UnknownReservation)
    }

    /// Reserve the listing-scoped pending-purchase slot before reveal
    /// dispatch. Idempotent; returns the slot ordinal.
    pub fn reserve_slot(
        &self,
        reservation_id: &str,
        now: u64,
    ) -> Result<u64, PurchaseCoordinatorError> {
        self.store
            .reserve_slot(reservation_id, now)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))
    }

    fn verify_reservation_admission(
        &self,
        reservation: &FindingPurchaseReservationRecord,
        admission: &SignedFindingAdmission,
    ) -> Result<(), PurchaseCoordinatorError> {
        chio_finding::verify_signed_admission(admission, &self.venue_authority, &self.venue_id)
            .map_err(|error| PurchaseCoordinatorError::AdmissionEnvelope(error.to_string()))?;
        let digest = canonical_json_bytes(admission)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        if digest != reservation.admission_envelope_sha256
            || admission.body.finding_id != reservation.finding_id
            || admission.body.listing_id != reservation.listing_id
        {
            return Err(PurchaseCoordinatorError::AdmissionMismatch);
        }
        for (role, policy, signing_key) in [
            (
                "purchase",
                &admission.body.purchase_authority,
                self.purchase_authority.public_key(),
            ),
            (
                "failed-delivery",
                &admission.body.failed_delivery_authority,
                self.failed_delivery_authority.public_key(),
            ),
        ] {
            if policy.key != signing_key {
                return Err(PurchaseCoordinatorError::DeclaredAuthorityMismatch(role));
            }
            if reservation.created_at < policy.valid_from
                || reservation.created_at > policy.valid_until
            {
                return Err(PurchaseCoordinatorError::DeclaredAuthorityWindow(role));
            }
        }
        Ok(())
    }

    fn verify_terminal(
        &self,
        reservation: &FindingPurchaseReservationRecord,
        receipt: &ChioReceipt,
        expected: ExpectedPurchaseTerminal,
    ) -> Result<VerifiedPurchaseTerminal, PurchaseCoordinatorError> {
        if !matches!(receipt.verify_signature(), Ok(true)) {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "receipt signature or content-addressed id is invalid".to_owned(),
            ));
        }
        let decision_matches = matches!(
            (expected, receipt.decision.as_ref()),
            (ExpectedPurchaseTerminal::Delivered, Some(Decision::Allow))
                | (
                    ExpectedPurchaseTerminal::Denied,
                    Some(Decision::Deny { .. })
                )
        );
        if !decision_matches {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "receipt decision does not authorize the requested terminal".to_owned(),
            ));
        }
        let metadata_object = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                PurchaseCoordinatorError::TerminalEvidence(
                    "receipt metadata is absent or malformed".to_owned(),
                )
            })?;
        let metadata: AdmissionReceiptMetadataV1 = metadata_object
            .get(ADMISSION_RECEIPT_METADATA_KEY)
            .cloned()
            .ok_or_else(|| {
                PurchaseCoordinatorError::TerminalEvidence(
                    "admission projection metadata is absent".to_owned(),
                )
            })
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| {
                    PurchaseCoordinatorError::TerminalEvidence(format!(
                        "admission projection metadata is invalid: {error}"
                    ))
                })
            })?;
        let operation = self
            .operations
            .load_by_operation_id(&metadata.operation_id)
            .map_err(|error| PurchaseCoordinatorError::TerminalEvidence(error.to_string()))?
            .ok_or_else(|| {
                PurchaseCoordinatorError::TerminalEvidence(
                    "projected admission operation is not durable".to_owned(),
                )
            })?;
        let expected_state = match expected {
            ExpectedPurchaseTerminal::Delivered => AdmissionOperationState::Completed,
            ExpectedPurchaseTerminal::Denied => AdmissionOperationState::DeniedAfterDelivery,
        };
        if operation.state() != expected_state
            || metadata.projected_state != expected_state
            || metadata.projected_operation_version != operation.version()
            || metadata.operation_id != *operation.binding().operation_id()
            || metadata.request_id != *operation.binding().request_id()
        {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "receipt projection conflicts with the durable operation".to_owned(),
            ));
        }
        match operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. })
                if receipt_id.as_str() == receipt.id => {}
            _ => {
                return Err(PurchaseCoordinatorError::TerminalEvidence(
                    "durable terminal does not replay this receipt".to_owned(),
                ));
            }
        }
        let delivery: FindingDelivery = metadata_object
            .get(FINDING_DELIVERY_METADATA_KEY)
            .cloned()
            .ok_or_else(|| {
                PurchaseCoordinatorError::TerminalEvidence(
                    "finding delivery metadata is absent".to_owned(),
                )
            })
            .and_then(|value| {
                serde_json::from_value(value).map_err(|error| {
                    PurchaseCoordinatorError::TerminalEvidence(format!(
                        "finding delivery metadata is invalid: {error}"
                    ))
                })
            })?;
        delivery
            .validate()
            .map_err(|error| PurchaseCoordinatorError::TerminalEvidence(error.to_string()))?;
        if delivery.finding_id != reservation.finding_id
            || delivery.listing_id != reservation.listing_id
            || delivery.reservation_id != reservation.reservation_id
            || delivery.purchase_intent_id != reservation.purchase_intent_id
            || delivery.authoritative_payment_operation_id
                != reservation.authoritative_payment_operation_id
            || delivery.venue_admission_envelope_sha256 != reservation.admission_envelope_sha256
            || delivery.settlement_mode != FindingDeliverySettlementMode::LocalReversibleHold
        {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "finding delivery metadata conflicts with the reservation".to_owned(),
            ));
        }
        match expected {
            ExpectedPurchaseTerminal::Delivered
                if delivery.digest_check != DeliveryResult::Matched
                    || delivery.media_type_check != FindingMediaTypeCheck::Matched =>
            {
                return Err(PurchaseCoordinatorError::TerminalEvidence(
                    "delivery terminal did not match the committed artifact".to_owned(),
                ));
            }
            ExpectedPurchaseTerminal::Denied
                if delivery.digest_check == DeliveryResult::Matched
                    && delivery.media_type_check == FindingMediaTypeCheck::Matched =>
            {
                return Err(PurchaseCoordinatorError::TerminalEvidence(
                    "denial terminal carries a successful delivery comparison".to_owned(),
                ));
            }
            _ => {}
        }
        let outcome = self
            .outcomes
            .lookup_by_operation(&metadata.operation_id)
            .map_err(|error| PurchaseCoordinatorError::TerminalEvidence(error.to_string()))?
            .ok_or_else(|| {
                PurchaseCoordinatorError::TerminalEvidence(
                    "durable tool outcome is absent".to_owned(),
                )
            })?;
        match expected {
            ExpectedPurchaseTerminal::Delivered => {
                if operation.tool_outcome_id() != Some(outcome.outcome_id())
                    || metadata.tool_outcome_id.as_ref() != Some(outcome.outcome_id())
                    || metadata.tool_outcome_version != Some(outcome.version())
                {
                    return Err(PurchaseCoordinatorError::TerminalEvidence(
                        "completed receipt does not bind the durable tool outcome".to_owned(),
                    ));
                }
            }
            ExpectedPurchaseTerminal::Denied => {
                if operation.tool_outcome_id() != Some(outcome.outcome_id())
                    || metadata.tool_outcome_id.is_some()
                    || metadata.tool_outcome_version.is_some()
                {
                    return Err(PurchaseCoordinatorError::TerminalEvidence(
                        "delivery denial does not bind its zero-charge outcome".to_owned(),
                    ));
                }
            }
        }
        let settlement = match outcome.disposition() {
            ResolvedToolOutcomeV1::Resolved {
                settlement_disposition,
                ..
            } => settlement_disposition.clone(),
            ResolvedToolOutcomeV1::Returned | ResolvedToolOutcomeV1::Frozen { .. } => {
                return Err(PurchaseCoordinatorError::TerminalEvidence(
                    "durable tool outcome is not resolved".to_owned(),
                ));
            }
        };
        Ok(VerifiedPurchaseTerminal {
            delivery,
            settlement,
        })
    }

    /// Close the purchase only after a durable kernel Allow whose resolved
    /// outcome captured funds. Every record fact comes from the durable
    /// reservation, signed receipt, venue admission, or admission-bound
    /// backing. The store admits the derived payout destination and closes
    /// the slot in one transaction.
    pub fn finalize_delivery(
        &self,
        reservation_id: &str,
        receipt: &ChioReceipt,
        admission: &SignedFindingAdmission,
        backing: &SignedFindingBondBacking,
        now: u64,
    ) -> Result<SignedFindingPurchaseRecord, PurchaseCoordinatorError> {
        let reservation = self.resolve(reservation_id)?;
        self.verify_reservation_admission(&reservation, admission)?;
        let terminal =
            self.verify_terminal(&reservation, receipt, ExpectedPurchaseTerminal::Delivered)?;
        let SettlementDispositionV1::Capture { amount } = terminal.settlement else {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "Allow terminal did not durably capture the purchase".to_owned(),
            ));
        };
        if amount.currency != reservation.currency {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "captured currency conflicts with the reservation".to_owned(),
            ));
        }
        let realized_spend_units = amount.units;
        if realized_spend_units > reservation.amount_units {
            return Err(PurchaseCoordinatorError::RealizedSpendAboveAcceptedPrice);
        }
        let seller_backing_envelope_sha256 = canonical_json_bytes(backing)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        if seller_backing_envelope_sha256 != admission.body.backing_envelope_sha256 {
            return Err(PurchaseCoordinatorError::SellerBacking(
                "envelope digest does not match the admission".to_owned(),
            ));
        }
        verify_signed_bond_backing(backing, &backing.body.collateral_authority)
            .map_err(|error| PurchaseCoordinatorError::SellerBacking(error.to_string()))?;
        let encumbrance = self
            .store
            .get_encumbrance(reservation_id)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
            .ok_or(PurchaseCoordinatorError::UnknownReservation)?;
        if backing.body.allocation_id != admission.body.backing_allocation_id
            || backing.body.allocation_id != encumbrance.allocation_id
            || backing.body.finding_id != reservation.finding_id
            || backing.body.listing_id != reservation.listing_id
            || backing.body.authorization_envelope_sha256
                != admission.body.seller_authorization_envelope_sha256
            || backing.body.maximum_sale_exposure.currency != reservation.currency
        {
            return Err(PurchaseCoordinatorError::SellerBacking(
                "backing is not bound to the reserved sale".to_owned(),
            ));
        }
        let liability_horizon_secs = backing
            .body
            .claim_horizon_secs
            .checked_add(backing.body.audit_horizon_secs)
            .and_then(|value| value.checked_add(backing.body.appeal_horizon_secs))
            .and_then(|value| value.checked_add(backing.body.settlement_buffer_secs))
            .ok_or_else(|| {
                PurchaseCoordinatorError::SellerBacking(
                    "liability retention horizon overflowed".to_owned(),
                )
            })?;
        let retention_expires_at = reservation
            .created_at
            .checked_add(liability_horizon_secs)
            .ok_or_else(|| {
                PurchaseCoordinatorError::SellerBacking(
                    "liability retention terminal overflowed".to_owned(),
                )
            })?;
        if retention_expires_at > backing.body.expires_at {
            return Err(PurchaseCoordinatorError::SellerBacking(
                "backing expires before the liability retention horizon".to_owned(),
            ));
        }
        let accepted_bid_envelope_sha256 = &terminal.delivery.accepted_bid_envelope_sha256;
        let delivery_receipt_id = &receipt.id;
        let payout_destination = &admission.body.payee_destination;
        let buyer = PublicKey::from_hex(&reservation.payer_hex)
            .map_err(|_| PurchaseCoordinatorError::Store("payer key malformed".to_owned()))?;
        let record = FindingPurchaseRecord {
            schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_owned(),
            purchase_key: derive_purchase_key(
                accepted_bid_envelope_sha256,
                &reservation.authoritative_payment_operation_id,
            ),
            purchase_intent_id: reservation.purchase_intent_id.clone(),
            authoritative_payment_operation_id: reservation
                .authoritative_payment_operation_id
                .clone(),
            buyer: buyer.clone(),
            payer: buyer,
            finding_id: reservation.finding_id.clone(),
            listing_id: reservation.listing_id.clone(),
            accepted_bid_envelope_sha256: accepted_bid_envelope_sha256.to_owned(),
            venue_admission_envelope_sha256: reservation.admission_envelope_sha256.clone(),
            accepted_price: chio_core::capability::scope::MonetaryAmount {
                units: reservation.amount_units,
                currency: reservation.currency.clone(),
            },
            realized_spend: chio_core::capability::scope::MonetaryAmount {
                units: realized_spend_units,
                currency: reservation.currency.clone(),
            },
            seller_backing_envelope_sha256,
            encumbrance_id: sha256_hex(
                format!("{ENCUMBRANCE_DOMAIN}\0{reservation_id}").as_bytes(),
            ),
            delivery_receipt_id: delivery_receipt_id.clone(),
            payment_reference: reservation.authoritative_payment_operation_id.clone(),
            payout_destination: payout_destination.clone(),
            // The record's instant is the reservation instant, a durable
            // fact fixed when the funds were committed. The store compares
            // retained bytes against a retry's bytes, so a finalize clock
            // inside the body would turn an honest crash-retry into an
            // unresolvable conflict; the reservation instant replays
            // byte-identically and does not move however long delivery took.
            recorded_at: reservation.created_at,
        };
        // The store retains these bytes forever and the close is one-shot,
        // so a body that fails its own validator must never be signed: it
        // would stand as the buyer's unverifiable proof of a settled sale.
        record
            .validate()
            .map_err(|error| PurchaseCoordinatorError::ArtifactValidation(error.to_string()))?;
        let signed = SignedFindingPurchaseRecord::sign(record, &self.purchase_authority)
            .map_err(|_| PurchaseCoordinatorError::Signing)?;
        let record_json =
            canonical_json_bytes(&signed).map_err(|_| PurchaseCoordinatorError::Canonical)?;
        let record_sha256 = sha256_hex(&record_json);
        self.store
            .close_slot_with_record(&FindingPurchaseDeliveryInput {
                reservation_id,
                purchase_key: &signed.body.purchase_key,
                record_json: &record_json,
                record_sha256: &record_sha256,
                delivery_receipt_id,
                payout_destination,
                retention_expires_at,
                now,
            })
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
        Ok(signed)
    }

    /// Close the purchase only after a durable kernel delivery Deny whose
    /// resolved outcome proves contractual zero charge. The supplied
    /// checkpoint must be signed by the same kernel and prove inclusion of
    /// the exact deny receipt; ids, digests, and the release terminal are
    /// derived only after those checks pass.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_denial(
        &self,
        reservation_id: &str,
        receipt: &ChioReceipt,
        admission: &SignedFindingAdmission,
        checkpoint: &KernelCheckpoint,
        inclusion_proof: &ReceiptInclusionProof,
        now: u64,
    ) -> Result<SignedFindingFailedDelivery, PurchaseCoordinatorError> {
        let reservation = self.resolve(reservation_id)?;
        self.verify_reservation_admission(&reservation, admission)?;
        let terminal =
            self.verify_terminal(&reservation, receipt, ExpectedPurchaseTerminal::Denied)?;
        let (currency, release_terminal) = match terminal.settlement {
            SettlementDispositionV1::ContractualZeroCharge { currency } => {
                (currency, FindingHoldReleaseTerminal::Released)
            }
            SettlementDispositionV1::Capture { .. } | SettlementDispositionV1::NotApplicable => {
                return Err(PurchaseCoordinatorError::TerminalEvidence(
                    "delivery Deny did not durably release at zero charge".to_owned(),
                ));
            }
        };
        if currency != reservation.currency {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "zero-charge currency conflicts with the reservation".to_owned(),
            ));
        }
        validate_checkpoint(checkpoint)
            .map_err(|error| PurchaseCoordinatorError::CheckpointEvidence(error.to_string()))?;
        if !matches!(verify_checkpoint_signature(checkpoint), Ok(true))
            || checkpoint.body.kernel_key != receipt.kernel_key
            || checkpoint.body.issued_at < receipt.timestamp
            || inclusion_proof.checkpoint_seq != checkpoint.body.checkpoint_seq
            || inclusion_proof.merkle_root != checkpoint.body.merkle_root
            || inclusion_proof.proof.tree_size != checkpoint.body.tree_size
            || inclusion_proof.leaf_index != inclusion_proof.proof.leaf_index
            || inclusion_proof.receipt_seq < checkpoint.body.batch_start_seq
            || inclusion_proof.receipt_seq > checkpoint.body.batch_end_seq
        {
            return Err(PurchaseCoordinatorError::CheckpointEvidence(
                "checkpoint or inclusion binding does not match the deny receipt".to_owned(),
            ));
        }
        let expected_leaf_index = inclusion_proof
            .receipt_seq
            .checked_sub(checkpoint.body.batch_start_seq)
            .and_then(|index| usize::try_from(index).ok())
            .ok_or_else(|| {
                PurchaseCoordinatorError::CheckpointEvidence(
                    "receipt sequence cannot be represented as a checkpoint leaf".to_owned(),
                )
            })?;
        let receipt_bytes =
            canonical_json_bytes(receipt).map_err(|_| PurchaseCoordinatorError::Canonical)?;
        if inclusion_proof.leaf_index != expected_leaf_index
            || !inclusion_proof.verify(&receipt_bytes, &checkpoint.body.merkle_root)
        {
            return Err(PurchaseCoordinatorError::CheckpointEvidence(
                "deny receipt is not included in the checkpoint".to_owned(),
            ));
        }
        let accepted_bid_envelope_sha256 = &terminal.delivery.accepted_bid_envelope_sha256;
        let deny_receipt_id = &receipt.id;
        let deny_receipt_sha256 = sha256_hex(&receipt_bytes);
        let deny_checkpoint_ref = format!(
            "{}#{}",
            checkpoint_log_id(checkpoint),
            checkpoint.body.checkpoint_seq
        );
        let deny_checkpoint_sha256 = checkpoint_body_sha256(&checkpoint.body)
            .map_err(|error| PurchaseCoordinatorError::CheckpointEvidence(error.to_string()))?;
        let buyer = PublicKey::from_hex(&reservation.payer_hex)
            .map_err(|_| PurchaseCoordinatorError::Store("payer key malformed".to_owned()))?;
        let mut artifact = FindingFailedDelivery {
            schema: FINDING_FAILED_DELIVERY_SCHEMA_V1.to_owned(),
            failed_delivery_id: String::new(),
            buyer,
            finding_id: reservation.finding_id.clone(),
            listing_id: reservation.listing_id.clone(),
            accepted_bid_envelope_sha256: accepted_bid_envelope_sha256.clone(),
            reservation_id: reservation.reservation_id.clone(),
            purchase_intent_id: reservation.purchase_intent_id.clone(),
            authoritative_payment_operation_id: reservation
                .authoritative_payment_operation_id
                .clone(),
            hold_attempt_reference: reservation.authoritative_payment_operation_id.clone(),
            release_terminal,
            deny_receipt_id: deny_receipt_id.clone(),
            deny_receipt_sha256,
            deny_checkpoint_ref,
            deny_checkpoint_sha256,
            realized_spend_units: 0,
            currency: reservation.currency.clone(),
            payout_eligible: false,
            // The reservation instant, not the close clock: the terminal id
            // is content-addressed over this body, so a clock here would
            // give every crash-retry a different identity for one denial.
            recorded_at: reservation.created_at,
        };
        artifact.failed_delivery_id = compute_failed_delivery_id(&artifact)
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        // The denial terminal is the buyer's only evidence that the hold
        // was released without capture, and the store keeps it forever, so
        // an artifact its own validator rejects must never be signed.
        artifact
            .validate()
            .map_err(|error| PurchaseCoordinatorError::ArtifactValidation(error.to_string()))?;
        let signed = SignedFindingFailedDelivery::sign(artifact, &self.failed_delivery_authority)
            .map_err(|_| PurchaseCoordinatorError::Signing)?;
        let record_json =
            canonical_json_bytes(&signed).map_err(|_| PurchaseCoordinatorError::Canonical)?;
        let record_sha256 = sha256_hex(&record_json);
        self.store
            .close_slot_with_deny(&FindingPurchaseDenyInput {
                reservation_id,
                failed_delivery_id: &signed.body.failed_delivery_id,
                record_json: &record_json,
                record_sha256: &record_sha256,
                deny_receipt_id,
                now,
            })
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
        Ok(signed)
    }

    /// Idempotently release a reservation whose purchase did not proceed.
    pub fn release(&self, reservation_id: &str, now: u64) -> Result<(), PurchaseCoordinatorError> {
        self.store
            .release_reservation(reservation_id, now)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))
    }
}

/// Reservation reader over the coordinator store for the kernel's
/// admission-time gate.
pub struct CoordinatorReservationReader {
    store: SqliteFindingPurchaseStore,
    admissions: SqliteFindingMarketStore,
}

impl CoordinatorReservationReader {
    #[must_use]
    pub fn new(store: SqliteFindingPurchaseStore, admissions: SqliteFindingMarketStore) -> Self {
        Self { store, admissions }
    }

    /// Convenience constructor returning the trait object the kernel
    /// verifier expects.
    #[must_use]
    pub fn shared(
        store: SqliteFindingPurchaseStore,
        admissions: SqliteFindingMarketStore,
    ) -> Arc<dyn PurchaseReservationReader> {
        Arc::new(Self::new(store, admissions))
    }
}

impl PurchaseReservationReader for CoordinatorReservationReader {
    fn verify_slot_reserved(
        &self,
        expectation: &ReservationExpectation<'_>,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        let record = self
            .store
            .get_reservation(expectation.reservation_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "reservation is not resolvable".to_owned())?;
        if record.state != FindingPurchaseReservationState::SlotReserved {
            return Err("reservation is not slot-reserved for this purchase".to_owned());
        }
        if now_unix_secs >= record.expires_at {
            return Err("reservation has expired at the purchase clock".to_owned());
        }
        if record.purchase_intent_id != expectation.purchase_intent_id
            || record.authoritative_payment_operation_id
                != expectation.authoritative_payment_operation_id
            || record.payer_hex != expectation.payer_key_hex
            || record.finding_id != expectation.finding_id
            || record.listing_id != expectation.listing_id
            || record.bid_envelope_sha256 != expectation.bid_request_envelope_sha256
            || record.admission_envelope_sha256 != expectation.admission_envelope_sha256
            || record.amount_units != expectation.amount_units
            || record.currency != expectation.currency
        {
            return Err("reservation does not bind this purchase".to_owned());
        }
        // The reservation was opened under one exact admission envelope.
        // Activation of a newer admission retires that envelope's terms
        // and collateral binding, so the reveal must not dispatch (and no
        // money must move) unless the reserved admission is still the
        // durable store's current one.
        let current = self
            .admissions
            .get_current_admission(&record.finding_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "no current admission covers the reserved finding".to_owned())?;
        if current.envelope_sha256 != record.admission_envelope_sha256 {
            return Err("reservation admission is superseded or retired".to_owned());
        }
        Ok(())
    }
}
