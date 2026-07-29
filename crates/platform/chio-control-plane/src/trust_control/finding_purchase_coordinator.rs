//! Single-operator purchase coordinator for finding sales.
//!
//! The pure marketplace accept does not reserve funds: it verifies a
//! supplied reservation receipt and copies its id. This coordinator is
//! the authoritative other half. After a bid it authenticates the buyer
//! key, verifies the exact signed ask against the current venue
//! admission, preallocates the stable purchase and payment identities,
//! atomically opens the budget reservation and the seller exposure
//! encumbrance in the durable purchase store, and only then signs the
//! minimal compatibility reservation receipt under the configured
//! purchase authority. Reveals re-resolve the durable record through the
//! accepted bid's receipt id; no caller-shaped value overrides it.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use std::sync::Arc;

use chio_core::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey};
use chio_finding::{
    compute_failed_delivery_id, derive_purchase_key, FindingFailedDelivery,
    FindingHoldReleaseTerminal, FindingPurchaseRecord, SignedFindingAdmission,
    SignedFindingFailedDelivery, SignedFindingPurchaseRecord, FINDING_FAILED_DELIVERY_SCHEMA_V1,
    FINDING_PURCHASE_RECORD_SCHEMA_V1,
};
use chio_open_market::bidding::{
    ReservationReceipt, SignedAskResponse, SignedReservationReceipt, RESERVATION_RECEIPT_SCHEMA,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};
use chio_store_sqlite::{
    FindingPurchaseDeliveryInput, FindingPurchaseDenyInput, FindingPurchaseReservationInput,
    FindingPurchaseReservationRecord, FindingPurchaseReservationState, SqliteFindingPurchaseStore,
};

use super::finding_purchase_verifier::{PurchaseReservationReader, ReservationExpectation};

/// Domain separator for the deterministic reservation identity.
const RESERVATION_DOMAIN: &str = "chio.finding.reservation.v1";

/// Domain separator for the deterministic encumbrance identity.
const ENCUMBRANCE_DOMAIN: &str = "chio.finding.encumbrance.v1";

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
    #[error("reserve request signature does not verify under the buyer key")]
    BuyerSignature,
    #[error("ask envelope rejected")]
    AskEnvelope,
    #[error("venue admission does not cover this sale")]
    AdmissionMismatch,
    #[error("purchase amounts must be exactly equal in units and currency")]
    AmountMismatch,
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
    purchase_authority: Keypair,
    failed_delivery_authority: Keypair,
}

impl FindingPurchaseCoordinator {
    /// Build the coordinator over the durable purchase store, verifying
    /// each signing key equals its configured public pin.
    pub fn new(
        store: SqliteFindingPurchaseStore,
        purchase_authority: Keypair,
        purchase_pin: &PublicKey,
        failed_delivery_authority: Keypair,
        failed_delivery_pin: &PublicKey,
    ) -> Result<Self, PurchaseCoordinatorError> {
        if purchase_authority.public_key() != *purchase_pin
            || failed_delivery_authority.public_key() != *failed_delivery_pin
        {
            return Err(PurchaseCoordinatorError::AuthorityPinMismatch);
        }
        Ok(Self {
            store,
            purchase_authority,
            failed_delivery_authority,
        })
    }

    /// Reserve funds and seller exposure for one accepted ask, then sign
    /// the compatibility reservation receipt.
    ///
    /// The buyer proves control of the token subject key by signing the
    /// exact ask digest; the venue admission freezes the sale identities;
    /// the allocation cap check and both reservations commit in one
    /// durable transaction. Replaying the same ask and payer returns the
    /// same signed receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &self,
        ask: &SignedAskResponse,
        buyer_signature_over_ask_digest: &str,
        admission: &SignedFindingAdmission,
        admission_envelope_sha256: &str,
        maximum_sale_exposure_units: u64,
        reservation_ttl_secs: u64,
        now: u64,
    ) -> Result<SignedReservationReceipt, PurchaseCoordinatorError> {
        if !matches!(ask.verify_signature(), Ok(true))
            || ask.body.token_offer.issuer != ask.signer_key
        {
            return Err(PurchaseCoordinatorError::AskEnvelope);
        }
        let ask_digest = canonical_json_bytes(&ask.body)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        let payer = &ask.body.token_offer.subject;
        let buyer_signature =
            chio_core::crypto::Signature::from_hex(buyer_signature_over_ask_digest)
                .map_err(|_| PurchaseCoordinatorError::BuyerSignature)?;
        if !payer.verify(ask_digest.as_bytes(), &buyer_signature) {
            return Err(PurchaseCoordinatorError::BuyerSignature);
        }
        if admission.body.listing_id != ask.body.listing_id {
            return Err(PurchaseCoordinatorError::AdmissionMismatch);
        }
        let [grant] = ask.body.token_offer.scope.grants.as_slice() else {
            return Err(PurchaseCoordinatorError::AskEnvelope);
        };
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
        let bid_envelope_sha256 = ask.body.bid_digest.clone();
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
            admission_envelope_sha256,
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

    /// Close the purchase after a settled Allow: sign the authoritative
    /// purchase record, retain the exposure through the liability
    /// horizon, admit the payout destination, and close the slot.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_delivery(
        &self,
        reservation_id: &str,
        delivery_receipt_id: &str,
        accepted_bid_envelope_sha256: &str,
        realized_spend_units: u64,
        payout_destination: &str,
        seller_backing_envelope_sha256: &str,
        retention_expires_at: u64,
        now: u64,
    ) -> Result<SignedFindingPurchaseRecord, PurchaseCoordinatorError> {
        let reservation = self.resolve(reservation_id)?;
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
            seller_backing_envelope_sha256: seller_backing_envelope_sha256.to_owned(),
            encumbrance_id: sha256_hex(
                format!("{ENCUMBRANCE_DOMAIN}\0{reservation_id}").as_bytes(),
            ),
            delivery_receipt_id: delivery_receipt_id.to_owned(),
            payment_reference: reservation.authoritative_payment_operation_id.clone(),
            payout_destination: payout_destination.to_owned(),
            recorded_at: now,
        };
        let signed = SignedFindingPurchaseRecord::sign(record, &self.purchase_authority)
            .map_err(|_| PurchaseCoordinatorError::Signing)?;
        let record_json =
            canonical_json_bytes(&signed).map_err(|_| PurchaseCoordinatorError::Canonical)?;
        let record_sha256 = sha256_hex(&record_json);
        self.store
            .admit_payout_destination(
                &self
                    .store
                    .get_encumbrance(reservation_id)
                    .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
                    .ok_or(PurchaseCoordinatorError::UnknownReservation)?
                    .allocation_id,
                payout_destination,
                now,
            )
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
        self.store
            .close_slot_with_record(&FindingPurchaseDeliveryInput {
                reservation_id,
                purchase_key: &signed.body.purchase_key,
                record_json: &record_json,
                record_sha256: &record_sha256,
                delivery_receipt_id,
                retention_expires_at,
                now,
            })
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
        Ok(signed)
    }

    /// Close the purchase after a checkpointed delivery denial: sign the
    /// standing artifact, release the exposure, and close the slot to
    /// the denial terminal. Until this completes the failure is pending
    /// and grants no standing.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_denial(
        &self,
        reservation_id: &str,
        accepted_bid_envelope_sha256: &str,
        deny_receipt_id: &str,
        deny_receipt_sha256: &str,
        deny_checkpoint_ref: &str,
        deny_checkpoint_sha256: &str,
        now: u64,
    ) -> Result<SignedFindingFailedDelivery, PurchaseCoordinatorError> {
        let reservation = self.resolve(reservation_id)?;
        let buyer = PublicKey::from_hex(&reservation.payer_hex)
            .map_err(|_| PurchaseCoordinatorError::Store("payer key malformed".to_owned()))?;
        let mut artifact = FindingFailedDelivery {
            schema: FINDING_FAILED_DELIVERY_SCHEMA_V1.to_owned(),
            failed_delivery_id: String::new(),
            buyer,
            finding_id: reservation.finding_id.clone(),
            listing_id: reservation.listing_id.clone(),
            accepted_bid_envelope_sha256: accepted_bid_envelope_sha256.to_owned(),
            reservation_id: reservation.reservation_id.clone(),
            purchase_intent_id: reservation.purchase_intent_id.clone(),
            authoritative_payment_operation_id: reservation
                .authoritative_payment_operation_id
                .clone(),
            hold_attempt_reference: reservation.authoritative_payment_operation_id.clone(),
            release_terminal: FindingHoldReleaseTerminal::Released,
            deny_receipt_id: deny_receipt_id.to_owned(),
            deny_receipt_sha256: deny_receipt_sha256.to_owned(),
            deny_checkpoint_ref: deny_checkpoint_ref.to_owned(),
            deny_checkpoint_sha256: deny_checkpoint_sha256.to_owned(),
            realized_spend_units: 0,
            currency: reservation.currency.clone(),
            payout_eligible: false,
            recorded_at: now,
        };
        artifact.failed_delivery_id = compute_failed_delivery_id(&artifact)
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
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
}

impl CoordinatorReservationReader {
    #[must_use]
    pub fn new(store: SqliteFindingPurchaseStore) -> Self {
        Self { store }
    }

    /// Convenience constructor returning the trait object the kernel
    /// verifier expects.
    #[must_use]
    pub fn shared(store: SqliteFindingPurchaseStore) -> Arc<dyn PurchaseReservationReader> {
        Arc::new(Self::new(store))
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
            || record.amount_units != expectation.amount_units
            || record.currency != expectation.currency
        {
            return Err("reservation does not bind this purchase".to_owned());
        }
        Ok(())
    }
}
