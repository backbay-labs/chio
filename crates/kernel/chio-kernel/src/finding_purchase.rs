//! Purchase-aware admission seam for delivery-committed finding reveals.
//!
//! A grant carrying [`Constraint::RequireFindingPurchase`] authorizes
//! exactly one purchased reveal. The kernel cannot depend on the market
//! crates that define the purchase artifacts, so verification is injected
//! behind [`FindingPurchaseVerifier`] the same way payment rails are: the
//! production implementation strict-parses the signed purchase context and
//! reads the authoritative reservation store, while the kernel owns the
//! fail-closed wiring and the cross-checks that bind the verified result
//! to the selected grant, the request, and the paying capability.
//!
//! The seam is split into a deterministic half and an admission-time half.
//! [`FindingPurchaseVerifier::verify_purchase`] must be a pure function of
//! the carrier bytes and marker: the durable finalizer re-runs it after a
//! crash from the frozen request, so any clock or store read there would
//! make recovery diverge from admission. Liveness bounds and reservation
//! state belong in
//! [`FindingPurchaseVerifier::verify_purchase_admission`], which runs only
//! before dispatch.

use chio_core::capability::scope::{FindingPurchaseMarkerV1, MonetaryAmount};
use chio_core::capability::token::CapabilityToken;

use crate::finding_denial::FindingDenial;

/// Governed-intent context key carrying the base64 canonical purchase
/// context for a marked reveal.
pub const FINDING_PURCHASE_CONTEXT_KEY: &str = "chio_finding_purchase_context_b64";

/// Governed-intent context key carrying the canonical portable finding-status
/// proof. The encoded value is verified by the kernel's injected status
/// verifier before a purchase-marked request can cross the dispatch boundary.
pub const FINDING_STATUS_PROOF_CONTEXT_KEY: &str = "chio_finding_status_proof_b64";

/// Maximum base64 status-proof carrier accepted at the kernel boundary.
///
/// This matches the portable proof artifact bound without making the kernel
/// depend on the experimental market artifact crate.
pub const MAX_FINDING_STATUS_PROOF_B64_BYTES: usize = 196_608;

/// Governed-intent context key reserved for the cross-organization escrow
/// witness. The local settlement rail rejects a request that carries it.
pub const FINDING_ESCROW_WITNESS_CONTEXT_KEY: &str = "chio_finding_escrow_witness_b64";

/// Receipt-metadata key carrying the durable, admission-verified purchase
/// binding used by terminal replay after authority rotation.
pub(crate) const FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY: &str =
    "finding_purchase_replay_snapshot";
#[cfg(feature = "finding-market")]
pub(crate) const FINDING_PURCHASE_REPLAY_SNAPSHOT_SCHEMA: &str =
    "chio.finding.purchase-replay-snapshot.v1";

/// Inputs to purchase verification for one marked reveal request.
pub struct FindingPurchaseContextView<'a> {
    /// The provider-signed marker on the selected grant.
    pub marker: &'a FindingPurchaseMarkerV1,
    /// The base64 canonical purchase context from the governed intent.
    pub context_b64: &'a str,
    /// The paying capability presented with the request.
    pub capability: &'a CapabilityToken,
    /// Target tool server.
    pub server_id: &'a str,
    /// Target tool name.
    pub tool_name: &'a str,
    /// The exact request arguments.
    pub arguments: &'a serde_json::Value,
    /// The output digest the selected grant committed to.
    pub expected_output_digest: &'a str,
}

/// Purchase facts recovered from the verified context, cross-checked by
/// the kernel against the selected grant before any money movement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedFindingPurchase {
    /// Content-addressed id of the finding being sold.
    pub finding_id: String,
    /// Listing the sale was admitted under.
    pub listing_id: String,
    /// The signed finding's payload commitment.
    pub payload_sha256: String,
    /// The signed finding's advertised reveal media type.
    pub payload_media_type: String,
    /// Status feed named by the independently verified signed finding.
    pub expected_status_feed_id: String,
    /// The accepted purchase price.
    pub accepted_price: MonetaryAmount,
    /// Hex public key of the paying buyer bound by the reservation.
    pub payer_key_hex: String,
    /// Authoritative reservation the purchase resolved through.
    pub reservation_id: String,
    /// Coordinator-preallocated purchase intent identity.
    pub purchase_intent_id: String,
    /// Coordinator-preallocated payment operation identity.
    pub authoritative_payment_operation_id: String,
    /// Canonical SHA-256 digest of the signed accepted-bid envelope.
    pub accepted_bid_envelope_sha256: String,
    /// Canonical SHA-256 digest of the venue-signed admission envelope.
    pub venue_admission_envelope_sha256: String,
    /// Kernel-verified portable live-status evidence. The option keeps older
    /// serialized receipts decodable, but new purchase admission requires it.
    pub status_proof: Option<VerifiedFindingStatusProof>,
}

/// Deterministic facts recovered from a verified portable non-inclusion
/// proof. Inclusion never produces this value: a retracted finding denies.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedFindingStatusProof {
    /// Governance-pinned status feed.
    pub feed_id: String,
    /// Fixed numeric key domain used to derive the sparse path.
    pub key_domain_nonce: u64,
    /// Monotonic signed map generation.
    pub map_epoch: u64,
    /// Content-addressed signed status epoch id.
    pub status_epoch_id: String,
    /// Digest of the exact canonical signed status epoch envelope bytes.
    pub status_epoch_artifact_sha256: String,
    /// Digest of the exact canonical portable proof input bytes.
    pub proof_sha256: String,
    /// Signed sparse-map root.
    pub root_hash: String,
    /// Trusted-time observation carried by the verified proof.
    pub non_inclusion_checked_at: u64,
    /// Governance authorization that admitted the status-operator key.
    pub operator_authorization_sha256: String,
    /// External evidence for the service bond live at verification time.
    pub service_bond_evidence_sha256: String,
}

/// Durable snapshot recorded with the authenticated raw tool return. The raw
/// outcome and immutable request hash bind this verified result to the exact
/// request that crossed dispatch, so terminal replay does not consult a newly
/// rotated authority configuration.
#[cfg(feature = "finding-market")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingPurchaseReplaySnapshotV1 {
    pub schema: String,
    pub purchase: VerifiedFindingPurchase,
}

#[cfg(feature = "finding-market")]
impl FindingPurchaseReplaySnapshotV1 {
    #[must_use]
    pub(crate) fn new(purchase: VerifiedFindingPurchase) -> Self {
        Self {
            schema: FINDING_PURCHASE_REPLAY_SNAPSHOT_SCHEMA.to_owned(),
            purchase,
        }
    }
}

/// Inputs to deterministic portable status-proof verification.
pub struct FindingStatusProofContextView<'a> {
    /// Base64 of exact canonical `chio.finding.status-proof-input.v1` bytes.
    pub proof_b64: &'a str,
    /// Finding id recovered from the independently verified purchase context.
    pub expected_finding_id: &'a str,
    /// Status feed recovered from the independently verified signed finding.
    pub expected_feed_id: &'a str,
}

/// Inputs for rechecking a previously delivered Finding against the current
/// governance-pinned status floor immediately before a derived mutation.
pub struct FindingCurrentStatusContextView<'a> {
    /// Finding id recovered from the authenticated delivery receipt.
    pub expected_finding_id: &'a str,
    /// Status feed recovered from the authenticated delivery receipt.
    pub expected_feed_id: &'a str,
    /// Oldest map epoch admitted by the original delivery.
    pub minimum_map_epoch: u64,
    /// Oldest trusted non-inclusion observation admitted by the delivery.
    pub minimum_non_inclusion_checked_at: u64,
}

/// Injected status verifier for finding purchases.
///
/// The deterministic half validates exact bytes, signatures, domains,
/// cross-bindings, and the sparse path. The admission half rechecks clocked
/// freshness and atomically consults/advances the durable feed floor and
/// sticky pending/retracted state. Keeping mutable state out of the first half
/// makes durable terminal replay a function of the frozen request.
pub trait FindingStatusProofVerifier: Send + Sync {
    /// Verify the portable proof without consulting clocks or mutable stores.
    fn verify_status_proof(
        &self,
        view: &FindingStatusProofContextView<'_>,
    ) -> Result<VerifiedFindingStatusProof, FindingDenial>;

    /// Enforce freshness and the durable monotonic/sticky admission policy.
    fn verify_status_admission(
        &self,
        view: &FindingStatusProofContextView<'_>,
        verified: &VerifiedFindingStatusProof,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial>;

    /// Recheck a previously delivered Finding against the verifier's current
    /// authenticated floor. Implementations without a durable current-status
    /// view fail closed.
    fn verify_current_status_admission(
        &self,
        _view: &FindingCurrentStatusContextView<'_>,
        _now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        Err(FindingDenial::unavailable(
            "current finding status admission is not supported by this verifier",
        ))
    }
}

/// Injected purchase-context verification for marked reveals.
///
/// Every error denies before a nonce, budget, payment authorization, or
/// dispatch mutation. A marked grant with no installed verifier denies the
/// same way.
pub trait FindingPurchaseVerifier: Send + Sync {
    /// Deterministically verify the purchase context against the marker.
    ///
    /// This half must depend only on the supplied view: the durable
    /// finalizer replays it from the frozen request, so implementations
    /// must not read clocks or mutable stores here.
    fn verify_purchase(
        &self,
        view: &FindingPurchaseContextView<'_>,
    ) -> Result<VerifiedFindingPurchase, FindingDenial>;

    /// Admission-time checks that may consult clocks and authoritative
    /// state: finding liveness bounds and the reservation being open and
    /// slot-reserved for exactly this purchase.
    fn verify_purchase_admission(
        &self,
        view: &FindingPurchaseContextView<'_>,
        verified: &VerifiedFindingPurchase,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial>;

    /// Persist the exact purchase's capture fence before the kernel calls a
    /// payment rail. Implementations must be idempotent: durable recovery can
    /// invoke this again after the payment journal has already selected the
    /// same capture.
    fn mark_capture_pending(
        &self,
        verified: &VerifiedFindingPurchase,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial>;
}
