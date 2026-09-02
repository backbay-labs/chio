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

use std::sync::Arc;

use chio_core::canonical_json_bytes;
use chio_core::capability::scope::{Constraint, FindingSettlementSelector, Operation};
use chio_core::crypto::{sha256_hex, Ed25519Backend, Keypair, PublicKey, SigningBackend};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::Decision;
use chio_core::receipt::metadata::{
    DeliveryResult, FindingDelivery, FindingDeliverySettlementMode, FindingMediaTypeCheck,
    FINDING_DELIVERY_METADATA_KEY,
};
use chio_finding::{
    compute_failed_delivery_id, derive_purchase_key, validate_evm_payout_destination,
    verify_finding, verify_signed_authority_status, verify_signed_bond_backing,
    verify_signed_failed_delivery, verify_signed_purchase_record,
    verify_signed_seller_authorization, Finding, FindingAuthorityKeyPolicy, FindingFailedDelivery,
    FindingHoldReleaseTerminal, FindingPurchaseRecord, SignedFindingAdmission,
    SignedFindingBondBacking, SignedFindingFailedDelivery, SignedFindingMarketTerms,
    SignedFindingPurchaseRecord, SignedFindingSellerAuthorization,
    FINDING_FAILED_DELIVERY_SCHEMA_V1, FINDING_PURCHASE_RECORD_SCHEMA_V1,
    FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1,
};
use chio_kernel::finding_denial::FindingDenial;

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
    FindingPublicPurchaseRequestBinding, FindingPurchaseDeliveryInput, FindingPurchaseDenyInput,
    FindingPurchaseReservationInput, FindingPurchaseReservationRecord,
    FindingPurchaseReservationState, SqliteAdmissionOperationStore, SqliteFindingMarketStore,
    SqliteFindingPurchaseStore, SqliteToolOutcomeStore,
};

use super::finding_challenge_coordinator::FindingAuthorityStatusResolver;
use super::finding_purchase_verifier::{PurchaseReservationReader, ReservationExpectation};
use super::service_types::{
    require_status_feed_through, FindingAuthorityPin, FindingStatusOperatorPin,
    FindingStatusServiceBond, FINDING_STATUS_MAX_EPOCH_AGE_SECS,
};

/// Domain separator for the deterministic reservation identity.
const RESERVATION_DOMAIN: &str = "chio.finding.reservation.v1";

/// Domain separator for the deterministic encumbrance identity.
const ENCUMBRANCE_DOMAIN: &str = "chio.finding.encumbrance.v1";

/// Maximum age of an independently signed revocation reading used to
/// authorize a new terminal signature.
const TERMINAL_AUTHORITY_STATUS_MAX_AGE_SECS: u64 = 3_600;

fn authority_policy_covers(policy: &FindingAuthorityKeyPolicy, instant: u64) -> bool {
    instant >= policy.valid_from && instant < policy.valid_until
}

fn require_purchase_terminal_window(
    policy: &FindingAuthorityKeyPolicy,
    recorded_at: u64,
) -> Result<(), PurchaseCoordinatorError> {
    if !authority_policy_covers(policy, recorded_at) {
        return Err(PurchaseCoordinatorError::DeclaredAuthorityWindow(
            "purchase",
        ));
    }
    Ok(())
}

fn require_failed_delivery_terminal_window(
    policy: &FindingAuthorityKeyPolicy,
    recorded_at: u64,
) -> Result<(), PurchaseCoordinatorError> {
    if !authority_policy_covers(policy, recorded_at) {
        return Err(PurchaseCoordinatorError::FailedDeliveryAuthorityWindow);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedPurchaseTerminal {
    Delivered,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityStatusReading {
    Current,
    PostTerminal { terminal_at: u64 },
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
    #[error("authority-status pin is invalid or aliases a terminal signing authority")]
    AuthorityStatusPin,
    #[error("configured status epoch age ceiling is invalid")]
    StatusEpochAge,
    #[error("listing authority pin is invalid or aliases another trusted authority")]
    ListingPin,
    #[error("venue authority pin is invalid or aliases another trusted authority")]
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
    #[error("finding participation binding rejected: {0}")]
    ParticipationBinding(String),
    #[error("admission-declared {0} authority is not the coordinator signing key")]
    DeclaredAuthorityMismatch(&'static str),
    #[error("admission-declared {0} authority window does not cover the reservation instant")]
    DeclaredAuthorityWindow(&'static str),
    #[error("admission-declared {role} authority lifecycle rejected terminal closure: {reason}")]
    AuthorityLifecycle {
        role: &'static str,
        reason: &'static str,
    },
    #[error(
        "admission-declared failed-delivery authority window does not cover the denial terminal"
    )]
    FailedDeliveryAuthorityWindow,
    #[error("seller authorization envelope rejected: {0}")]
    SellerAuthorization(String),
    #[error("seller authorization is not the admission-bound envelope for this sale")]
    SellerAuthorizationBinding,
    #[error("seller authorization is not live at the supplied clock")]
    SellerAuthorizationWindow,
    #[error("seller authorization lifecycle rejected the reservation: {0}")]
    SellerAuthorizationLifecycle(&'static str),
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
    #[error("reservation settlement window is empty or unrepresentable")]
    ReservationWindow,
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
    purchase_authority: Arc<dyn SigningBackend>,
    failed_delivery_authority: Arc<dyn SigningBackend>,
    authority_status: Arc<dyn FindingAuthorityStatusResolver>,
    authority_status_pin: FindingAuthorityPin,
    status_feed_operator: FindingStatusOperatorPin,
    status_feed_service_bond: FindingStatusServiceBond,
    status_max_epoch_age_secs: u64,
    listing_authority: FindingAuthorityPin,
    venue_authority: FindingAuthorityPin,
    venue_id: String,
}

impl FindingPurchaseCoordinator {
    /// Build the coordinator over the durable purchase store and the
    /// market store whose admission lifecycle gates every sale, verifying
    /// each signing key equals its configured public pin and that the
    /// venue authority policy is valid and names the admissions this
    /// coordinator accepts.
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
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        authority_status_pin: &FindingAuthorityPin,
        status_feed_operator: &FindingStatusOperatorPin,
        status_feed_service_bond: &FindingStatusServiceBond,
        status_max_epoch_age_secs: u64,
        listing_pin: &FindingAuthorityPin,
        venue_pin: &FindingAuthorityPin,
        venue_id: &str,
    ) -> Result<Self, PurchaseCoordinatorError> {
        Self::new_with_signing_backends(
            store,
            admissions,
            operations,
            outcomes,
            Arc::new(Ed25519Backend::new(purchase_authority)),
            purchase_pin,
            Arc::new(Ed25519Backend::new(failed_delivery_authority)),
            failed_delivery_pin,
            authority_status,
            authority_status_pin,
            status_feed_operator,
            status_feed_service_bond,
            status_max_epoch_age_secs,
            listing_pin,
            venue_pin,
            venue_id,
        )
    }

    /// Build with custody-backed purchase and failed-delivery signers.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_signing_backends(
        store: SqliteFindingPurchaseStore,
        admissions: SqliteFindingMarketStore,
        operations: SqliteAdmissionOperationStore,
        outcomes: SqliteToolOutcomeStore,
        purchase_authority: Arc<dyn SigningBackend>,
        purchase_pin: &PublicKey,
        failed_delivery_authority: Arc<dyn SigningBackend>,
        failed_delivery_pin: &PublicKey,
        authority_status: Arc<dyn FindingAuthorityStatusResolver>,
        authority_status_pin: &FindingAuthorityPin,
        status_feed_operator: &FindingStatusOperatorPin,
        status_feed_service_bond: &FindingStatusServiceBond,
        status_max_epoch_age_secs: u64,
        listing_pin: &FindingAuthorityPin,
        venue_pin: &FindingAuthorityPin,
        venue_id: &str,
    ) -> Result<Self, PurchaseCoordinatorError> {
        if purchase_authority.public_key() != *purchase_pin
            || failed_delivery_authority.public_key() != *failed_delivery_pin
            || purchase_authority.public_key() == failed_delivery_authority.public_key()
        {
            return Err(PurchaseCoordinatorError::AuthorityPinMismatch);
        }
        let authority_status_key = authority_status_pin
            .validate("authority-status")
            .map_err(|_| PurchaseCoordinatorError::AuthorityStatusPin)?;
        let status_operator_key = status_feed_operator
            .require_live(
                &status_feed_operator.feed_id,
                status_feed_operator.authority.valid_from,
            )
            .map_err(|_| PurchaseCoordinatorError::AuthorityStatusPin)?;
        status_feed_service_bond
            .validate(status_feed_operator)
            .map_err(|_| PurchaseCoordinatorError::AuthorityStatusPin)?;
        if authority_status_key == purchase_authority.public_key()
            || authority_status_key == failed_delivery_authority.public_key()
            || authority_status_key == status_operator_key
        {
            return Err(PurchaseCoordinatorError::AuthorityStatusPin);
        }
        if status_max_epoch_age_secs == 0
            || status_max_epoch_age_secs > FINDING_STATUS_MAX_EPOCH_AGE_SECS
        {
            return Err(PurchaseCoordinatorError::StatusEpochAge);
        }
        let listing_key = listing_pin
            .validate("listing")
            .map_err(|_| PurchaseCoordinatorError::ListingPin)?;
        if listing_key == purchase_authority.public_key()
            || listing_key == failed_delivery_authority.public_key()
            || listing_key == authority_status_key
            || listing_key == status_operator_key
        {
            return Err(PurchaseCoordinatorError::ListingPin);
        }
        let venue_key = venue_pin
            .validate("venue")
            .map_err(|_| PurchaseCoordinatorError::VenuePin)?;
        if venue_id.is_empty()
            || venue_key == purchase_authority.public_key()
            || venue_key == failed_delivery_authority.public_key()
            || venue_key == authority_status_key
            || venue_key == status_operator_key
            || venue_key == listing_key
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
            authority_status,
            authority_status_pin: authority_status_pin.clone(),
            status_feed_operator: status_feed_operator.clone(),
            status_feed_service_bond: status_feed_service_bond.clone(),
            status_max_epoch_age_secs,
            listing_authority: listing_pin.clone(),
            venue_authority: venue_pin.clone(),
            venue_id: venue_id.to_owned(),
        })
    }

    fn require_live_configured_authority(
        &self,
        policy: &FindingAuthorityPin,
        now: u64,
        role: &'static str,
    ) -> Result<PublicKey, PurchaseCoordinatorError> {
        let reject = |reason| PurchaseCoordinatorError::AuthorityLifecycle { role, reason };
        if !self.authority_status_pin.covers(now) {
            return Err(reject("authority-status signer window is not live"));
        }
        if !policy.covers(now) {
            return Err(reject("configured authority window is not live"));
        }
        let configured_key = policy
            .key()
            .map_err(|_| reject("configured authority key is invalid"))?;
        let signed = self
            .authority_status
            .resolve(policy, now)
            .map_err(|_| reject("revocation source could not be resolved"))?;
        let authority_status_key = self
            .authority_status_pin
            .key()
            .map_err(|_| reject("authority-status signer key is invalid"))?;
        verify_signed_authority_status(&signed, &authority_status_key)
            .map_err(|_| reject("revocation status signature is invalid"))?;
        let status = &signed.body;
        if !self.authority_status_pin.covers(status.observed_at) {
            return Err(reject(
                "revocation status was signed outside the authority-status window",
            ));
        }
        if !policy.covers(status.observed_at) {
            return Err(reject(
                "revocation status was observed outside the configured authority window",
            ));
        }
        if status.status_ref != policy.revocation_status_ref
            || status.authority_id != policy.authority_id
            || status.key != configured_key
            || status.key_epoch != policy.key_epoch
        {
            return Err(reject(
                "revocation status does not bind the configured authority policy",
            ));
        }
        if status.observed_at > now
            || now.saturating_sub(status.observed_at) > TERMINAL_AUTHORITY_STATUS_MAX_AGE_SECS
        {
            return Err(reject("revocation status is not a fresh current reading"));
        }
        if status
            .revoked_from
            .is_some_and(|revoked_from| revoked_from <= now)
        {
            return Err(reject("authority is revoked at reservation"));
        }
        Ok(configured_key)
    }

    fn require_live_listing_authority(
        &self,
        now: u64,
    ) -> Result<PublicKey, PurchaseCoordinatorError> {
        self.require_live_configured_authority(&self.listing_authority, now, "listing")
    }

    fn require_live_venue_authority(
        &self,
        now: u64,
    ) -> Result<PublicKey, PurchaseCoordinatorError> {
        self.require_live_configured_authority(&self.venue_authority, now, "venue")
    }

    fn require_live_terminal_authority(
        &self,
        policy: &FindingAuthorityKeyPolicy,
        signing_key: &PublicKey,
        reading: AuthorityStatusReading,
        now: u64,
        role: &'static str,
    ) -> Result<u64, PurchaseCoordinatorError> {
        let reject = |reason| PurchaseCoordinatorError::AuthorityLifecycle { role, reason };
        if !self.authority_status_pin.covers(now) {
            return Err(reject("authority-status signer window is not live"));
        }
        if policy.key != *signing_key {
            return Err(PurchaseCoordinatorError::DeclaredAuthorityMismatch(role));
        }
        if !authority_policy_covers(policy, now)
            || matches!(
                reading,
                AuthorityStatusReading::PostTerminal { terminal_at }
                    if !authority_policy_covers(policy, terminal_at)
            )
        {
            return Err(reject("configured authority window is not live"));
        }
        let signed = self
            .authority_status
            .resolve(
                &super::service_types::FindingAuthorityPin {
                    authority_id: policy.authority_id.clone(),
                    key_hex: policy.key.to_hex(),
                    key_epoch: policy.key_epoch,
                    valid_from: policy.valid_from,
                    valid_until: policy.valid_until,
                    revocation_status_ref: policy.revocation_status_ref.clone(),
                },
                now,
            )
            .map_err(|_| reject("revocation source could not be resolved"))?;
        let authority_status_key = self
            .authority_status_pin
            .key()
            .map_err(|_| reject("authority-status signer key is invalid"))?;
        verify_signed_authority_status(&signed, &authority_status_key)
            .map_err(|_| reject("revocation status signature is invalid"))?;
        let status = &signed.body;
        if !self.authority_status_pin.covers(status.observed_at) {
            return Err(reject(
                "revocation status was signed outside the authority-status window",
            ));
        }
        if !authority_policy_covers(policy, status.observed_at) {
            return Err(reject(
                "revocation status was observed outside the admitted authority window",
            ));
        }
        if status.status_ref != policy.revocation_status_ref
            || status.authority_id != policy.authority_id
            || status.key != policy.key
            || status.key_epoch != policy.key_epoch
        {
            return Err(reject(
                "revocation status does not bind the admitted policy",
            ));
        }
        if status.observed_at > now
            || now.saturating_sub(status.observed_at) > TERMINAL_AUTHORITY_STATUS_MAX_AGE_SECS
            || matches!(
                reading,
                AuthorityStatusReading::PostTerminal { terminal_at }
                    if status.observed_at < terminal_at
            )
        {
            return Err(reject(match reading {
                AuthorityStatusReading::Current => {
                    "revocation status is not a fresh current reading"
                }
                AuthorityStatusReading::PostTerminal { .. } => {
                    "revocation status is not a fresh post-terminal reading"
                }
            }));
        }
        if status
            .revoked_from
            .is_some_and(|revoked_from| revoked_from <= now)
        {
            return Err(reject(match reading {
                AuthorityStatusReading::Current => "authority is revoked at reservation",
                AuthorityStatusReading::PostTerminal { .. } => {
                    "authority is revoked at finalization"
                }
            }));
        }
        Ok(status.observed_at)
    }

    fn require_live_status_operator(
        &self,
        feed_id: &str,
        now: u64,
    ) -> Result<(&str, u64), PurchaseCoordinatorError> {
        let key = require_status_feed_through(
            &self.status_feed_operator,
            &self.status_feed_service_bond,
            feed_id,
            now,
            now,
        )
        .map_err(|_| PurchaseCoordinatorError::AuthorityLifecycle {
            role: "status-operator",
            reason: "configured operator authorization or service bond is not live",
        })?;
        let policy = FindingAuthorityKeyPolicy {
            authority_id: self.status_feed_operator.authority.authority_id.clone(),
            key: key.clone(),
            key_epoch: self.status_feed_operator.authority.key_epoch,
            valid_from: self.status_feed_operator.authority.valid_from,
            valid_until: self.status_feed_operator.authority.valid_until,
            rotation_policy_ref: self.status_feed_operator.rotation_policy_ref.clone(),
            revocation_status_ref: self
                .status_feed_operator
                .authority
                .revocation_status_ref
                .clone(),
        };
        let observed_at = self.require_live_terminal_authority(
            &policy,
            &key,
            AuthorityStatusReading::Current,
            now,
            "status-operator",
        )?;
        Ok((&self.status_feed_operator.authorization_sha256, observed_at))
    }

    fn require_live_seller_authorization(
        &self,
        authorization: &SignedFindingSellerAuthorization,
        now: u64,
    ) -> Result<(), PurchaseCoordinatorError> {
        let reject = PurchaseCoordinatorError::SellerAuthorizationLifecycle;
        if !self.authority_status_pin.covers(now) {
            return Err(reject("authority-status signer window is not live"));
        }
        let body = &authorization.body;
        let pin = FindingAuthorityPin {
            authority_id: body.authorization_id.clone(),
            key_hex: body.issuer.to_hex(),
            key_epoch: FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1,
            valid_from: body.issued_at,
            valid_until: body.expires_at,
            revocation_status_ref: body.revocation_status_ref.clone(),
        };
        let signed = self
            .authority_status
            .resolve(&pin, now)
            .map_err(|_| reject("revocation source could not be resolved"))?;
        let status_key = self
            .authority_status_pin
            .key()
            .map_err(|_| reject("authority-status signer key is invalid"))?;
        verify_signed_authority_status(&signed, &status_key)
            .map_err(|_| reject("revocation status signature is invalid"))?;
        let status = &signed.body;
        if !self.authority_status_pin.covers(status.observed_at) {
            return Err(reject(
                "revocation status was signed outside the authority-status window",
            ));
        }
        if status.status_ref != body.revocation_status_ref
            || status.authority_id != body.authorization_id
            || status.key != body.issuer
            || status.key_epoch != FINDING_SELLER_AUTHORIZATION_KEY_EPOCH_V1
        {
            return Err(reject(
                "revocation status does not bind the seller authorization",
            ));
        }
        if status.observed_at < body.issued_at
            || status.observed_at > now
            || now.saturating_sub(status.observed_at) > TERMINAL_AUTHORITY_STATUS_MAX_AGE_SECS
        {
            return Err(reject("revocation status is not a fresh current reading"));
        }
        if status
            .revoked_from
            .is_some_and(|revoked_from| revoked_from <= now)
        {
            return Err(reject("seller authorization is revoked"));
        }
        Ok(())
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
        self.reserve_inner(
            bid,
            ask,
            buyer_signature_over_ask_digest,
            admission,
            seller_authorization,
            maximum_sale_exposure_units,
            reservation_ttl_secs,
            now,
            None,
        )
    }

    /// Reserve for a public request and atomically retain its complete buyer
    /// policy beside the reservation. Exact replays verify the same immutable
    /// binding without requiring the admission to remain current.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_for_public_request(
        &self,
        bid: &SignedBidRequest,
        ask: &SignedAskResponse,
        buyer_signature_over_ask_digest: &str,
        admission: &SignedFindingAdmission,
        seller_authorization: &SignedFindingSellerAuthorization,
        maximum_sale_exposure_units: u64,
        reservation_ttl_secs: u64,
        now: u64,
        public_request: &FindingPublicPurchaseRequestBinding<'_>,
    ) -> Result<SignedReservationReceipt, PurchaseCoordinatorError> {
        self.reserve_inner(
            bid,
            ask,
            buyer_signature_over_ask_digest,
            admission,
            seller_authorization,
            maximum_sale_exposure_units,
            reservation_ttl_secs,
            now,
            Some(public_request),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_inner(
        &self,
        bid: &SignedBidRequest,
        ask: &SignedAskResponse,
        buyer_signature_over_ask_digest: &str,
        admission: &SignedFindingAdmission,
        seller_authorization: &SignedFindingSellerAuthorization,
        maximum_sale_exposure_units: u64,
        reservation_ttl_secs: u64,
        now: u64,
        public_request: Option<&FindingPublicPurchaseRequestBinding<'_>>,
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
        // Agent identity remains the capability subject. Cognition-market
        // bids separately carry the buyer's settlement address inside the
        // signed bid body, which the reservation retains through terminal
        // settlement. Reject an absent or unusable address before funds or
        // seller exposure are reserved.
        let payout_destination = bid.body.payout_destination.as_deref().ok_or_else(|| {
            PurchaseCoordinatorError::PayoutDestination(
                "signed bid omits payout_destination".to_owned(),
            )
        })?;
        let payout_destination = chio_finding::canonical_evm_payout_destination(payout_destination)
            .map_err(|error| PurchaseCoordinatorError::PayoutDestination(error.to_string()))?;
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
        let venue_authority = self.venue_authority.key().map_err(|_| {
            PurchaseCoordinatorError::AuthorityLifecycle {
                role: "venue",
                reason: "configured authority key is invalid",
            }
        })?;
        chio_finding::verify_signed_admission(admission, &venue_authority, &self.venue_id)
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
            if !authority_policy_covers(policy, now) {
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
        let requested_expiry = now
            .checked_add(reservation_ttl_secs)
            .ok_or(PurchaseCoordinatorError::ReservationWindow)?;
        let expires_at = requested_expiry
            .min(ask.body.expires_at)
            .min(ask.body.token_offer.expires_at)
            .min(admission.body.expires_at)
            .min(self.authority_status_pin.valid_until)
            .min(self.listing_authority.valid_until)
            .min(self.venue_authority.valid_until)
            .min(admission.body.purchase_authority.valid_until)
            .min(admission.body.failed_delivery_authority.valid_until)
            .min(authorization.expires_at);
        let replay_probe_expires_at = if expires_at > now {
            expires_at
        } else {
            now.checked_add(1)
                .ok_or(PurchaseCoordinatorError::ReservationWindow)?
        };
        let mut input = FindingPurchaseReservationInput {
            reservation_id: &reservation_id,
            purchase_intent_id: &derive_purchase_intent_id(&reservation_id),
            authoritative_payment_operation_id: &derive_payment_operation_id(&reservation_id),
            payer_hex: &payer_hex,
            agent_id: &ask.body.agent_id,
            payout_destination: &payout_destination,
            finding_id: &admission.body.finding_id,
            listing_id: &ask.body.listing_id,
            bid_envelope_sha256: &bid_envelope_sha256,
            ask_digest: &ask_digest,
            admission_envelope_sha256: &admission_envelope_sha256,
            fee_schedule_envelope_sha256: &admission.body.fee_schedule_envelope_sha256,
            // The exact replay probe compares immutable purchase identity and
            // ignores this new-reservation-only value. It is populated from
            // the current admission before any new reservation is opened.
            participation_epoch: 0,
            amount_units: ask.body.quoted_price.units,
            currency: &ask.body.quoted_price.currency,
            expires_at: replay_probe_expires_at,
            encumbrance_id: &encumbrance_id,
            allocation_id: &admission.body.backing_allocation_id,
            maximum_sale_exposure_units,
            created_at: now,
        };
        let exact_replay = self
            .store
            .is_exact_reservation_replay(&input)
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
        if exact_replay {
            if let Some(public_request) = public_request {
                self.store
                    .verify_public_purchase_reservation(public_request, &reservation_id)
                    .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
            }
        } else {
            // A newer activation may supersede this admission after a
            // reservation committed but before its response arrived. Exact
            // durable replay above recovers that receipt; only a new
            // reservation requires the presented admission to remain current.
            let current = self
                .admissions
                .get_current_admission(&admission.body.finding_id)
                .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
                .ok_or(PurchaseCoordinatorError::AdmissionNotCurrent)?;
            if current.envelope_sha256 != admission_envelope_sha256 {
                return Err(PurchaseCoordinatorError::AdmissionNotCurrent);
            }
            if now < current.activated_at {
                return Err(PurchaseCoordinatorError::ParticipationBinding(
                    "reservation clock predates admission activation".to_owned(),
                ));
            }
            let terms_bytes = self
                .admissions
                .get_recipe_blob(&admission.body.terms_envelope_sha256)
                .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
                .ok_or_else(|| {
                    PurchaseCoordinatorError::ParticipationBinding(
                        "admission-bound terms are not retained".to_owned(),
                    )
                })?;
            let terms: SignedFindingMarketTerms =
                serde_json::from_slice(&terms_bytes).map_err(|_| {
                    PurchaseCoordinatorError::ParticipationBinding(
                        "admission-bound terms are malformed".to_owned(),
                    )
                })?;
            terms.body.validate().map_err(|error| {
                PurchaseCoordinatorError::ParticipationBinding(error.to_string())
            })?;
            if terms.body.finding_id != admission.body.finding_id
                || terms.body.listing_id != admission.body.listing_id
            {
                return Err(PurchaseCoordinatorError::ParticipationBinding(
                    "admission-bound terms name another sale".to_owned(),
                ));
            }
            input.participation_epoch =
                now.saturating_sub(current.activated_at) / terms.body.audit_epoch_length_secs;
            self.require_live_listing_authority(now)?;
            self.require_live_venue_authority(now)?;
            if expires_at <= now {
                return Err(PurchaseCoordinatorError::ReservationWindow);
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
                self.require_live_terminal_authority(
                    policy,
                    &signing_key,
                    AuthorityStatusReading::Current,
                    now,
                    role,
                )?;
            }
            self.require_live_seller_authorization(seller_authorization, now)?;
            input.expires_at = expires_at;
            let status_operator_observed_at = self
                .require_live_status_operator(&finding.status_feed_ref, now)?
                .1;
            match public_request {
                Some(public_request) => self.store.open_live_public_reservation(
                    &input,
                    public_request,
                    &finding.status_feed_ref,
                    &self.status_feed_operator.authorization_sha256,
                    status_operator_observed_at,
                    now,
                    self.status_max_epoch_age_secs,
                ),
                None => self.store.open_live_reservation(
                    &input,
                    &finding.status_feed_ref,
                    &self.status_feed_operator.authorization_sha256,
                    status_operator_observed_at,
                    now,
                    self.status_max_epoch_age_secs,
                ),
            }
            .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?;
        }
        let receipt = ReservationReceipt {
            schema: RESERVATION_RECEIPT_SCHEMA.to_owned(),
            receipt_id: reservation_id,
            agent_id: ask.body.agent_id.clone(),
            listing_id: ask.body.listing_id.clone(),
            ask_digest,
            reserved_amount: ask.body.quoted_price.clone(),
        };
        SignedReservationReceipt::sign_with_backend(receipt, self.purchase_authority.as_ref())
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
        let venue_authority = self
            .venue_authority
            .key()
            .map_err(|_| PurchaseCoordinatorError::VenuePin)?;
        chio_finding::verify_signed_admission(admission, &venue_authority, &self.venue_id)
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
            if !authority_policy_covers(policy, reservation.created_at) {
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

    fn verify_terminal_chronology(
        reservation: &FindingPurchaseReservationRecord,
        receipt: &ChioReceipt,
        terminal: &'static str,
    ) -> Result<(), PurchaseCoordinatorError> {
        if receipt.timestamp < reservation.created_at {
            return Err(PurchaseCoordinatorError::TerminalEvidence(format!(
                "{terminal} receipt predates the purchase reservation"
            )));
        }
        if receipt.timestamp >= reservation.expires_at {
            return Err(PurchaseCoordinatorError::TerminalEvidence(format!(
                "{terminal} receipt is outside the reservation settlement window"
            )));
        }
        Ok(())
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
        if receipt.timestamp > now {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "delivery receipt is ahead of the finalization clock".to_owned(),
            ));
        }
        Self::verify_terminal_chronology(&reservation, receipt, "delivery")?;
        let terminal =
            self.verify_terminal(&reservation, receipt, ExpectedPurchaseTerminal::Delivered)?;
        require_purchase_terminal_window(&admission.body.purchase_authority, receipt.timestamp)?;
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
        let retention_expires_at = receipt
            .timestamp
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
        let buyer = PublicKey::from_hex(&reservation.payer_hex)
            .map_err(|_| PurchaseCoordinatorError::Store("payer key malformed".to_owned()))?;
        let payout_destination = reservation.payout_destination.clone();
        validate_evm_payout_destination(&payout_destination)
            .map_err(|error| PurchaseCoordinatorError::PayoutDestination(error.to_string()))?;
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
            // The signed receipt fixes the settlement instant. It replays
            // byte-identically across crash recovery while binding standing
            // to the purchase authority lifecycle when capture completed.
            recorded_at: receipt.timestamp,
        };
        // The store retains these bytes forever and the close is one-shot,
        // so a body that fails its own validator must never be signed: it
        // would stand as the buyer's unverifiable proof of a settled sale.
        record
            .validate()
            .map_err(|error| PurchaseCoordinatorError::ArtifactValidation(error.to_string()))?;
        if reservation.state == FindingPurchaseReservationState::Consumed {
            let retained = self
                .store
                .get_purchase_record(&record.purchase_key)
                .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
                .ok_or_else(|| {
                    PurchaseCoordinatorError::Store(
                        "consumed reservation lost its purchase record".to_owned(),
                    )
                })?;
            let signed: SignedFindingPurchaseRecord = serde_json::from_slice(&retained.record_json)
                .map_err(|_| {
                    PurchaseCoordinatorError::Store(
                        "retained purchase record failed deserialization".to_owned(),
                    )
                })?;
            verify_signed_purchase_record(&signed, &admission.body.purchase_authority.key)
                .map_err(|error| PurchaseCoordinatorError::ArtifactValidation(error.to_string()))?;
            if signed.body != record {
                return Err(PurchaseCoordinatorError::Store(
                    "retained purchase record conflicts with replay inputs".to_owned(),
                ));
            }
            return Ok(signed);
        }
        self.require_live_terminal_authority(
            &admission.body.purchase_authority,
            &self.purchase_authority.public_key(),
            AuthorityStatusReading::PostTerminal {
                terminal_at: receipt.timestamp,
            },
            now,
            "purchase",
        )?;
        let signed = SignedFindingPurchaseRecord::sign_with_backend(
            record,
            self.purchase_authority.as_ref(),
        )
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
                payout_destination: &payout_destination,
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
        if receipt.timestamp > now {
            return Err(PurchaseCoordinatorError::TerminalEvidence(
                "denial receipt is ahead of the finalization clock".to_owned(),
            ));
        }
        Self::verify_terminal_chronology(&reservation, receipt, "denial")?;
        let terminal =
            self.verify_terminal(&reservation, receipt, ExpectedPurchaseTerminal::Denied)?;
        require_failed_delivery_terminal_window(
            &admission.body.failed_delivery_authority,
            receipt.timestamp,
        )?;
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
        if checkpoint.body.issued_at > now {
            return Err(PurchaseCoordinatorError::CheckpointEvidence(
                "denial checkpoint is ahead of the finalization clock".to_owned(),
            ));
        }
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
            venue_admission_envelope_sha256: reservation.admission_envelope_sha256.clone(),
            seller_backing_envelope_sha256: admission.body.backing_envelope_sha256.clone(),
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
            // The authenticated denial receipt fixes the closure instant, so
            // crash retries reproduce one content-addressed terminal while
            // the authority remains accountable through the denial time.
            recorded_at: receipt.timestamp,
        };
        artifact.failed_delivery_id = compute_failed_delivery_id(&artifact)
            .map_err(|_| PurchaseCoordinatorError::Canonical)?;
        // The denial terminal is the buyer's only evidence that the hold
        // was released without capture, and the store keeps it forever, so
        // an artifact its own validator rejects must never be signed.
        artifact
            .validate()
            .map_err(|error| PurchaseCoordinatorError::ArtifactValidation(error.to_string()))?;
        if reservation.state == FindingPurchaseReservationState::Released {
            if let Some(retained) = self
                .store
                .get_failed_delivery_record(&artifact.failed_delivery_id)
                .map_err(|error| PurchaseCoordinatorError::Store(error.to_string()))?
            {
                let signed: SignedFindingFailedDelivery =
                    serde_json::from_slice(&retained.record_json).map_err(|_| {
                        PurchaseCoordinatorError::Store(
                            "retained failed-delivery record failed deserialization".to_owned(),
                        )
                    })?;
                verify_signed_failed_delivery(
                    &signed,
                    &admission.body.failed_delivery_authority.key,
                )
                .map_err(|error| PurchaseCoordinatorError::ArtifactValidation(error.to_string()))?;
                if signed.body != artifact {
                    return Err(PurchaseCoordinatorError::Store(
                        "retained failed-delivery record conflicts with replay inputs".to_owned(),
                    ));
                }
                return Ok(signed);
            }
        }
        self.require_live_terminal_authority(
            &admission.body.failed_delivery_authority,
            &self.failed_delivery_authority.public_key(),
            AuthorityStatusReading::PostTerminal {
                terminal_at: receipt.timestamp,
            },
            now,
            "failed-delivery",
        )?;
        let signed = SignedFindingFailedDelivery::sign_with_backend(
            artifact,
            self.failed_delivery_authority.as_ref(),
        )
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

    /// Move one due reservation to the durable expired terminal.
    pub fn expire_reservation(
        &self,
        reservation_id: &str,
        now: u64,
    ) -> Result<bool, PurchaseCoordinatorError> {
        self.store
            .expire_reservation(reservation_id, now)
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
    ) -> Result<(), FindingDenial> {
        let record = self
            .store
            .get_reservation(expectation.reservation_id)
            .map_err(|error| FindingDenial::unavailable(error.to_string()))?
            .ok_or_else(|| FindingDenial::binding_mismatch("reservation is not resolvable"))?;
        if record.state != FindingPurchaseReservationState::SlotReserved {
            return Err(FindingDenial::stale_or_superseded(
                "reservation is not slot-reserved for this purchase",
            ));
        }
        if now_unix_secs >= record.expires_at {
            return Err(FindingDenial::stale_or_superseded(
                "reservation has expired at the purchase clock",
            ));
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
            return Err(FindingDenial::binding_mismatch(
                "reservation does not bind this purchase",
            ));
        }
        // The reservation was opened under one exact admission envelope.
        // Activation of a newer admission retires that envelope's terms
        // and collateral binding, so the reveal must not dispatch (and no
        // money must move) unless the reserved admission is still the
        // durable store's current one.
        let current = self
            .admissions
            .get_current_admission(&record.finding_id)
            .map_err(|error| FindingDenial::unavailable(error.to_string()))?
            .ok_or_else(|| {
                FindingDenial::stale_or_superseded(
                    "no current admission covers the reserved finding",
                )
            })?;
        if current.envelope_sha256 != record.admission_envelope_sha256 {
            return Err(FindingDenial::stale_or_superseded(
                "reservation admission is superseded or retired",
            ));
        }
        Ok(())
    }

    fn mark_capture_pending(
        &self,
        reservation_id: &str,
        authoritative_payment_operation_id: &str,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        self.store
            .mark_capture_pending(
                reservation_id,
                authoritative_payment_operation_id,
                now_unix_secs,
            )
            .map(|_| ())
            .map_err(|error| FindingDenial::unavailable(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_delivery_terminal_must_precede_the_authority_boundary() {
        let policy = FindingAuthorityKeyPolicy {
            authority_id: "failed-delivery".to_owned(),
            key: chio_core::crypto::Keypair::from_seed(&[17_u8; 32]).public_key(),
            key_epoch: 1,
            valid_from: 100,
            valid_until: 200,
            rotation_policy_ref: "rotation-policy-v1".to_owned(),
            revocation_status_ref: "revocations/failed-delivery".to_owned(),
        };

        assert!(require_failed_delivery_terminal_window(&policy, 199).is_ok());
        assert!(matches!(
            require_failed_delivery_terminal_window(&policy, 200),
            Err(PurchaseCoordinatorError::FailedDeliveryAuthorityWindow)
        ));
    }

    #[test]
    fn purchase_terminal_must_precede_the_authority_boundary() {
        let policy = FindingAuthorityKeyPolicy {
            authority_id: "purchase".to_owned(),
            key: chio_core::crypto::Keypair::from_seed(&[16_u8; 32]).public_key(),
            key_epoch: 1,
            valid_from: 100,
            valid_until: 200,
            rotation_policy_ref: "rotation-policy-v1".to_owned(),
            revocation_status_ref: "revocations/purchase".to_owned(),
        };

        assert!(require_purchase_terminal_window(&policy, 199).is_ok());
        assert!(matches!(
            require_purchase_terminal_window(&policy, 200),
            Err(PurchaseCoordinatorError::DeclaredAuthorityWindow(
                "purchase"
            ))
        ));
    }
}
