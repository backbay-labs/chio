//! Kernel-facing purchase verifier over the market verification core.
//!
//! The kernel's injected seam splits verification into a deterministic
//! half and an admission-time half. This adapter delegates the
//! deterministic half to the pure market core and the admission-time
//! half to finding liveness plus an authoritative reservation reader, so
//! the kernel itself never grows a market dependency.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use std::sync::Arc;

use chio_kernel::finding_purchase::{
    FindingPurchaseContextView, FindingPurchaseVerifier, VerifiedFindingPurchase,
};
use chio_open_market::purchase_verification::{
    verify_purchase_context_pure, PurchaseVerificationAuthorities, PurchaseVerificationInputs,
};

/// The exact reservation facts the admission-time check requires the
/// authoritative store to confirm.
pub struct ReservationExpectation<'a> {
    pub reservation_id: &'a str,
    pub purchase_intent_id: &'a str,
    pub authoritative_payment_operation_id: &'a str,
    pub payer_key_hex: &'a str,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub amount_units: u64,
    pub currency: &'a str,
}

/// Authoritative reservation state consulted only at admission time.
///
/// Implementations read the coordinator's durable store: the reservation
/// must exist under exactly the expected identities and amounts, be in
/// its slot-reserved state, and be unexpired at `now_unix_secs`. Every
/// error denies the reveal before dispatch.
pub trait PurchaseReservationReader: Send + Sync {
    fn verify_slot_reserved(
        &self,
        expectation: &ReservationExpectation<'_>,
        now_unix_secs: u64,
    ) -> Result<(), String>;
}

/// Production purchase verifier: pure market verification plus the
/// authoritative reservation gate.
pub struct MarketFindingPurchaseVerifier {
    authorities: PurchaseVerificationAuthorities,
    reservations: Arc<dyn PurchaseReservationReader>,
}

impl MarketFindingPurchaseVerifier {
    #[must_use]
    pub fn new(
        authorities: PurchaseVerificationAuthorities,
        reservations: Arc<dyn PurchaseReservationReader>,
    ) -> Self {
        Self {
            authorities,
            reservations,
        }
    }

    fn inputs<'a>(view: &'a FindingPurchaseContextView<'_>) -> PurchaseVerificationInputs<'a> {
        PurchaseVerificationInputs {
            marker_finding_id: &view.marker.finding_id,
            marker_listing_id: &view.marker.listing_id,
            expected_output_digest: view.expected_output_digest,
            context_b64: view.context_b64,
            capability: view.capability,
            server_id: view.server_id,
            tool_name: view.tool_name,
            arguments: view.arguments,
        }
    }
}

impl FindingPurchaseVerifier for MarketFindingPurchaseVerifier {
    fn verify_purchase(
        &self,
        view: &FindingPurchaseContextView<'_>,
    ) -> Result<VerifiedFindingPurchase, String> {
        let outcome = verify_purchase_context_pure(&Self::inputs(view), &self.authorities)
            .map_err(|error| error.to_string())?;
        Ok(VerifiedFindingPurchase {
            finding_id: outcome.finding.finding_id.clone(),
            listing_id: view.marker.listing_id.clone(),
            payload_sha256: outcome.finding.payload_sha256.clone(),
            payload_media_type: outcome.finding.payload_media_type.clone(),
            accepted_price: outcome.accepted_price.clone(),
            payer_key_hex: outcome.payer_key_hex.clone(),
            reservation_id: outcome.reservation_id.clone(),
            purchase_intent_id: outcome.purchase_intent_id.clone(),
            authoritative_payment_operation_id: outcome.authoritative_payment_operation_id.clone(),
            accepted_bid_envelope_sha256: outcome.accepted_bid_envelope_sha256.clone(),
            venue_admission_envelope_sha256: outcome.venue_admission_envelope_sha256.clone(),
        })
    }

    fn verify_purchase_admission(
        &self,
        view: &FindingPurchaseContextView<'_>,
        verified: &VerifiedFindingPurchase,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        // The pure half already proved the carrier; re-derive it here for
        // the clocked bounds so the admission check reads the same signed
        // facts, never caller-supplied ones.
        let outcome = verify_purchase_context_pure(&Self::inputs(view), &self.authorities)
            .map_err(|error| error.to_string())?;
        if now_unix_secs < outcome.finding.issued_at {
            return Err("finding is not yet live at the purchase clock".to_owned());
        }
        if now_unix_secs >= outcome.finding.expires_at {
            return Err("finding has expired at the purchase clock".to_owned());
        }
        if now_unix_secs < outcome.admission.body.issued_at {
            return Err("venue admission is not yet live at the purchase clock".to_owned());
        }
        if now_unix_secs >= outcome.admission.body.expires_at {
            return Err("venue admission has expired at the purchase clock".to_owned());
        }
        if now_unix_secs < outcome.seller_authorization.body.issued_at {
            return Err("seller authorization is not yet live at the purchase clock".to_owned());
        }
        if now_unix_secs >= outcome.seller_authorization.body.expires_at {
            return Err("seller authorization has expired at the purchase clock".to_owned());
        }
        self.reservations.verify_slot_reserved(
            &ReservationExpectation {
                reservation_id: &verified.reservation_id,
                purchase_intent_id: &verified.purchase_intent_id,
                authoritative_payment_operation_id: &verified.authoritative_payment_operation_id,
                payer_key_hex: &verified.payer_key_hex,
                finding_id: &verified.finding_id,
                listing_id: &verified.listing_id,
                amount_units: verified.accepted_price.units,
                currency: &verified.accepted_price.currency,
            },
            now_unix_secs,
        )
    }
}
