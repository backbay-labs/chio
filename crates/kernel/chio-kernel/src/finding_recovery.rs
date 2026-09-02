//! No-charge finding-redelivery admission seam.
//!
//! Recovery is intentionally separate from purchase admission. A recovery
//! grant carries [`Constraint::RequireFindingRecovery`], has no monetary
//! ceilings, and never reaches a payment participant. A product verifier
//! re-verifies the recovery evidence carrier, while its durable quota backend
//! atomically reserves an attempt under the deterministic recovery id before
//! dispatch and records the resulting receipt lineage after terminalization.

use chio_core::capability::scope::FindingRecoveryMarkerV1;
use chio_core::capability::token::CapabilityToken;

use crate::finding_denial::FindingDenial;

/// Top-level argument carrying the base64 canonical recovery context.
pub const FINDING_RECOVERY_CONTEXT_ARGUMENT: &str = "chio_finding_recovery_context_b64";

/// Inputs to deterministic recovery verification.
pub struct FindingRecoveryContextView<'a> {
    pub marker: &'a FindingRecoveryMarkerV1,
    pub context_b64: &'a str,
    pub recovery_capability: &'a CapabilityToken,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub arguments: &'a serde_json::Value,
    pub expected_output_digest: &'a str,
}

/// Facts recovered from the fully verified carrier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedFindingRecovery {
    pub recovery_id: String,
    pub finding_id: String,
    pub listing_id: String,
    pub payload_sha256: String,
    pub expected_status_feed_id: String,
    pub original_capability_id: String,
    pub original_delivery_receipt_id: String,
    pub purchase_key: String,
    pub original_subject_key_hex: String,
}

/// Receipt-metadata key carrying the durable recovery binding and the exact
/// live-status floor admitted immediately before dispatch.
pub(crate) const FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY: &str =
    "finding_recovery_replay_snapshot";
#[cfg(feature = "finding-market")]
pub(crate) const FINDING_RECOVERY_REPLAY_SNAPSHOT_SCHEMA: &str =
    "chio.finding.recovery-replay-snapshot.v1";

/// Dispatch-frozen recovery facts used only as minima for a new current-floor
/// lookup. Terminal replay never re-authenticates this old proof under a newly
/// rotated operator key.
#[cfg(feature = "finding-market")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FindingRecoveryReplaySnapshotV1 {
    pub(crate) schema: String,
    /// Canonical digest of the exact durable request and selected grant that
    /// produced these verified facts. Replay can therefore reject mutation
    /// without re-authenticating historical evidence under rotated keys.
    pub(crate) request_binding_sha256: String,
    pub(crate) recovery: VerifiedFindingRecovery,
    pub(crate) status: crate::finding_purchase::VerifiedFindingStatusProof,
}

#[cfg(feature = "finding-market")]
impl FindingRecoveryReplaySnapshotV1 {
    #[must_use]
    pub(crate) fn new(
        request_binding_sha256: String,
        recovery: VerifiedFindingRecovery,
        status: crate::finding_purchase::VerifiedFindingStatusProof,
    ) -> Self {
        Self {
            schema: FINDING_RECOVERY_REPLAY_SNAPSHOT_SCHEMA.to_owned(),
            request_binding_sha256,
            recovery,
            status,
        }
    }
}

/// Injected recovery verification, durable quota, and receipt-lineage seam.
pub trait FindingRecoveryVerifier: Send + Sync {
    /// Purely re-verify every artifact in the carrier and return only derived
    /// facts. This method is replayed by the durable finalizer.
    fn verify_recovery(
        &self,
        view: &FindingRecoveryContextView<'_>,
    ) -> Result<VerifiedFindingRecovery, FindingDenial>;

    /// Atomically reserve one durable attempt. Implementations must be
    /// idempotent on `(recovery_id, request_id)` and enforce one shared count
    /// across token re-mints and process restarts.
    fn reserve_recovery_attempt(
        &self,
        verified: &VerifiedFindingRecovery,
        request_id: &str,
        max_recoveries: u32,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial>;

    /// Persist the authenticated lineage from a recovery receipt back to the
    /// original paid delivery. Replays of the same receipt must be no-ops;
    /// conflicting lineage must reject.
    fn record_recovery_receipt(
        &self,
        verified: &VerifiedFindingRecovery,
        recovery_receipt_id: &str,
        recorded_at: u64,
    ) -> Result<(), FindingDenial>;
}
