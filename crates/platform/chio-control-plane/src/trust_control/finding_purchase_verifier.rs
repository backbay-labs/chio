//! Kernel-facing purchase verifier over the market verification core.
//!
//! The kernel's injected seam splits verification into a deterministic
//! half and an admission-time half. This adapter delegates the
//! deterministic half to the pure market core and the admission-time
//! half to finding liveness plus an authoritative reservation reader, so
//! the kernel itself never grows a market dependency.

use std::sync::Arc;

use chio_kernel::finding_denial::{FindingDenial, FindingDenialCode};
use chio_kernel::finding_purchase::{
    FindingPurchaseContextView, FindingPurchaseVerifier, VerifiedFindingPurchase,
};
use chio_open_market::purchase_verification::{
    verify_purchase_context_pure, PurchaseVerificationAuthorities, PurchaseVerificationError,
    PurchaseVerificationInputs,
};

/// Classify a pure-verification rejection into the seam's closed denial
/// vocabulary, preserving the exact prose.
fn purchase_denial(error: PurchaseVerificationError) -> FindingDenial {
    use PurchaseVerificationError as E;
    let code = match &error {
        E::Carrier(_) | E::Member(_) | E::MediaTypeMissing => FindingDenialCode::CarrierInvalid,
        E::Finding(_)
        | E::EnvelopeSignature(_)
        | E::Admission(_)
        | E::SellerAuthorization(_)
        | E::UnauthorizedIssuer
        | E::ReservationReceipt => FindingDenialCode::AuthorityInvalid,
        E::MarkerMismatch
        | E::PayloadDigestMismatch
        | E::AdmissionBindingMismatch(_)
        | E::SellerAuthorizationScope
        | E::HandshakeBinding(_)
        | E::TokenByteMismatch
        | E::ReservationBinding(_)
        | E::ArgumentMismatch => FindingDenialCode::BindingMismatch,
    };
    FindingDenial::new(code, error.to_string())
}

/// The exact reservation facts the admission-time check requires the
/// authoritative store to confirm.
pub struct ReservationExpectation<'a> {
    pub reservation_id: &'a str,
    pub purchase_intent_id: &'a str,
    pub authoritative_payment_operation_id: &'a str,
    pub payer_key_hex: &'a str,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub bid_request_envelope_sha256: &'a str,
    pub admission_envelope_sha256: &'a str,
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
    ) -> Result<(), FindingDenial>;

    fn mark_capture_pending(
        &self,
        reservation_id: &str,
        authoritative_payment_operation_id: &str,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial>;
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
    ) -> Result<VerifiedFindingPurchase, FindingDenial> {
        let outcome = verify_purchase_context_pure(&Self::inputs(view), &self.authorities)
            .map_err(purchase_denial)?;
        Ok(VerifiedFindingPurchase {
            finding_id: outcome.finding.finding_id.clone(),
            listing_id: view.marker.listing_id.clone(),
            payload_sha256: outcome.finding.payload_sha256.clone(),
            payload_media_type: outcome.finding.payload_media_type.clone(),
            expected_status_feed_id: outcome.finding.status_feed_ref.clone(),
            accepted_price: outcome.accepted_price.clone(),
            payer_key_hex: outcome.payer_key_hex.clone(),
            reservation_id: outcome.reservation_id.clone(),
            purchase_intent_id: outcome.purchase_intent_id.clone(),
            authoritative_payment_operation_id: outcome.authoritative_payment_operation_id.clone(),
            accepted_bid_envelope_sha256: outcome.accepted_bid_envelope_sha256.clone(),
            venue_admission_envelope_sha256: outcome.venue_admission_envelope_sha256.clone(),
            status_proof: None,
        })
    }

    fn verify_purchase_admission(
        &self,
        view: &FindingPurchaseContextView<'_>,
        verified: &VerifiedFindingPurchase,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        // The pure half already proved the carrier; re-derive it here for
        // the clocked bounds so the admission check reads the same signed
        // facts, never caller-supplied ones.
        let outcome = verify_purchase_context_pure(&Self::inputs(view), &self.authorities)
            .map_err(purchase_denial)?;
        let clock_bounds = [
            (
                outcome.finding.issued_at,
                outcome.finding.expires_at,
                "finding",
            ),
            (
                outcome.admission.body.issued_at,
                outcome.admission.body.expires_at,
                "venue admission",
            ),
            (
                outcome.seller_authorization.body.issued_at,
                outcome.seller_authorization.body.expires_at,
                "seller authorization",
            ),
        ];
        for (issued_at, expires_at, subject) in clock_bounds {
            if now_unix_secs < issued_at {
                return Err(FindingDenial::stale_or_superseded(format!(
                    "{subject} is not yet live at the purchase clock"
                )));
            }
            if now_unix_secs >= expires_at {
                return Err(FindingDenial::stale_or_superseded(format!(
                    "{subject} has expired at the purchase clock"
                )));
            }
        }
        self.reservations.verify_slot_reserved(
            &ReservationExpectation {
                reservation_id: &verified.reservation_id,
                purchase_intent_id: &verified.purchase_intent_id,
                authoritative_payment_operation_id: &verified.authoritative_payment_operation_id,
                payer_key_hex: &verified.payer_key_hex,
                finding_id: &verified.finding_id,
                listing_id: &verified.listing_id,
                bid_request_envelope_sha256: &outcome.bid_request_envelope_sha256,
                admission_envelope_sha256: &outcome.venue_admission_envelope_sha256,
                amount_units: verified.accepted_price.units,
                currency: &verified.accepted_price.currency,
            },
            now_unix_secs,
        )
    }

    fn mark_capture_pending(
        &self,
        verified: &VerifiedFindingPurchase,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        self.reservations.mark_capture_pending(
            &verified.reservation_id,
            &verified.authoritative_payment_operation_id,
            now_unix_secs,
        )
    }
}
